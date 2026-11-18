"""Fail-closed Phase 158 admission handoff preparation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .army_expansion import ArmyExpansionRoadmap
from .attack_vectors import AttackVectorCatalog
from .candidate_adapter_evidence import (
    BLOCKED_STATUS,
    GATE_STAGES,
    CandidateDevelopmentGateCatalog,
)
from .candidate_adapter_runner import ContainmentBackendAttestation
from .candidate_adapter_sdk import AdapterManifest, CandidateAdapterCatalog
from .candidate_backend_conformance import (
    BackendAdmissionReceipt,
    BackendConformanceReport,
    ContainmentConformanceSuiteCatalog,
)
from .candidate_execution_evidence_import import VerifiedCandidateExecutionEvidence
from .errors import QualificationError
from .qualification import QualificationStandard, _canonical_json, _canonical_sha256
from .qualification_plans_v2 import QualificationPlanCatalogV2
from .registry import ExpertRegistry
from .routing import CapabilityCatalog
from .types import ProfileKind

HANDOFF_DOMAIN = "sunderkey.phase158-admission-handoff.v1"
BLOCKER_DOMAIN = "sunderkey.phase158-admission-blocker-assessment.v1"
PLAN_ENTRY_DOMAIN = "sunderkey.phase158-qualification-plan-entry.v1"
PROFILE_DOMAIN = "sunderkey.phase158-review-profile.v1"
ADAPTER_CATALOG_DOMAIN = "sunderkey.candidate-adapter-catalog.v1"
HANDOFF_ID_PATTERN = re.compile(r"PAH-[0-9A-F]{32}")
ASSESSMENT_ID_PATTERN = re.compile(r"PAB-[0-9A-F]{32}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
EFFECT_FIELDS = (
    "qualification_effect",
    "routing_effect",
    "deployment_effect",
    "target_authority_effect",
)
CURRENT_BLOCKERS = (
    "containment_development_gate_blocked",
    "backend_admission_missing",
    "verified_candidate_execution_evidence_missing",
)


def _utc(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise QualificationError(f"{label} must use UTC Z notation")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise QualificationError(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.microsecond:
        raise QualificationError(f"{label} must be whole-second UTC")
    return value


def _content_identity(
    raw: dict[str, Any],
    *,
    domain: str,
    id_field: str,
    hash_field: str,
    prefix: str,
    pattern: re.Pattern[str],
) -> tuple[str, str]:
    identifier = raw.get(id_field)
    digest = raw.get(hash_field)
    if not isinstance(identifier, str) or pattern.fullmatch(identifier) is None:
        raise QualificationError(f"{id_field} is invalid")
    if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
        raise QualificationError(f"{hash_field} is invalid")
    body = {key: value for key, value in raw.items() if key not in {id_field, hash_field}}
    expected_digest = _canonical_sha256({"domain": domain, "document": body})
    expected_id = f"{prefix}-{expected_digest.removeprefix('sha256:')[:32].upper()}"
    if digest != expected_digest or identifier != expected_id:
        raise QualificationError("Phase 158 document identity does not match content")
    return identifier, digest


def _adapter_catalog_is_canonical(catalog: CandidateAdapterCatalog) -> None:
    raw = catalog.to_dict()
    body = {key: value for key, value in raw.items() if key != "catalog_sha256"}
    digest = _canonical_sha256({"domain": ADAPTER_CATALOG_DOMAIN, "catalog": body})
    if digest != catalog.catalog_sha256 or raw.get("catalog_sha256") != digest:
        raise QualificationError("Candidate adapter catalog is not content-addressed")
    manifests = tuple(AdapterManifest.from_dict(item) for item in raw.get("manifests", ()))
    if manifests != catalog.manifests:
        raise QualificationError("Candidate adapter catalog is not canonical")


@dataclass(frozen=True)
class _StaticBindings:
    plan: dict[str, Any]
    plan_sha256: str
    gate_sha256: tuple[str, ...]
    commander_id: str
    commander_sha256: str
    validator_id: str
    validator_sha256: str


def _validate_static_bindings(
    *,
    manifest: AdapterManifest,
    adapter_catalog: CandidateAdapterCatalog,
    development_gates: CandidateDevelopmentGateCatalog,
    qualification_plans: QualificationPlanCatalogV2,
    registry: ExpertRegistry,
    capabilities: CapabilityCatalog,
    vectors: AttackVectorCatalog,
    roadmap: ArmyExpansionRoadmap,
    standard: QualificationStandard,
) -> _StaticBindings:
    if AdapterManifest.from_dict(manifest.to_dict()) != manifest:
        raise QualificationError("Phase 158 adapter manifest is not canonical")
    _adapter_catalog_is_canonical(adapter_catalog)
    selected_manifest = adapter_catalog.manifests_by_profile_id.get(manifest.profile_id)
    if selected_manifest != manifest:
        raise QualificationError("Phase 158 adapter manifest is not in the adapter catalog")
    verified_gates = CandidateDevelopmentGateCatalog.from_dict(
        development_gates.to_dict(), adapter_catalog
    )
    if verified_gates != development_gates:
        raise QualificationError("Phase 157 development gates are not canonical")

    verified_registry = ExpertRegistry.from_dict(registry.to_dict())
    verified_capabilities = capabilities.revalidated(verified_registry)
    verified_vectors = AttackVectorCatalog.from_dict(vectors.to_dict(), verified_registry, roadmap)
    verified_plans = QualificationPlanCatalogV2.from_dict(
        qualification_plans.to_dict(),
        verified_registry,
        verified_capabilities,
        verified_vectors,
        standard,
    )
    if (
        verified_registry != registry
        or verified_capabilities != capabilities
        or verified_vectors != vectors
        or verified_plans != qualification_plans
    ):
        raise QualificationError("Phase 158 planning inputs are not canonical")

    plan = qualification_plans.plans_by_profile_id.get(manifest.profile_id)
    if plan is None or plan.get("vector_id") != manifest.vector_id:
        raise QualificationError("Army v2 qualification plan does not match the manifest")
    specialist = registry.profiles_by_id.get(manifest.profile_id)
    if (
        specialist is None
        or specialist.kind is not ProfileKind.SPECIALIST
        or specialist.command_id is None
    ):
        raise QualificationError("Phase 158 specialist profile is invalid")
    command = registry.commands_by_id.get(specialist.command_id)
    if command is None or manifest.profile_id not in command.specialist_profile_ids:
        raise QualificationError("Phase 158 specialist command membership is invalid")
    commander = registry.profiles_by_id.get(command.commander_profile_id)
    if commander is None or commander.kind is not ProfileKind.DOMAIN_COMMANDER:
        raise QualificationError("Phase 158 domain commander is invalid")
    validator_id = plan.get("independent_validator_id")
    validator = registry.profiles_by_id.get(validator_id)
    if (
        validator is None
        or validator.kind is not ProfileKind.SHARED
        or validator.id in {specialist.id, commander.id}
    ):
        raise QualificationError("Phase 158 independent validator is invalid")

    records = development_gates.records_by_profile_id.get(manifest.profile_id, ())
    if (
        len(records) != len(GATE_STAGES)
        or tuple(item["stage"] for item in records) != GATE_STAGES
        or any(item["manifest_sha256"] != manifest.manifest_sha256 for item in records)
        or records[GATE_STAGES.index("containment")]["status"] != BLOCKED_STATUS
    ):
        raise QualificationError("Phase 157 development gates do not match the manifest")
    plan_sha256 = _canonical_sha256({"domain": PLAN_ENTRY_DOMAIN, "plan": plan})
    commander_sha256 = _canonical_sha256({"domain": PROFILE_DOMAIN, "profile": commander.to_dict()})
    validator_sha256 = _canonical_sha256({"domain": PROFILE_DOMAIN, "profile": validator.to_dict()})
    return _StaticBindings(
        plan=dict(plan),
        plan_sha256=plan_sha256,
        gate_sha256=tuple(item["gate_sha256"] for item in records),
        commander_id=commander.id,
        commander_sha256=commander_sha256,
        validator_id=validator.id,
        validator_sha256=validator_sha256,
    )


def _validate_dynamic_bindings(
    *,
    manifest: AdapterManifest,
    verified_evidence: VerifiedCandidateExecutionEvidence,
    backend_admission: BackendAdmissionReceipt,
    attestation: ContainmentBackendAttestation,
    conformance_catalog: ContainmentConformanceSuiteCatalog,
    conformance_report: BackendConformanceReport,
) -> None:
    VerifiedCandidateExecutionEvidence.__post_init__(verified_evidence)
    if ContainmentBackendAttestation.from_dict(attestation.to_dict()) != attestation:
        raise QualificationError("Containment backend attestation is not canonical")
    verified_catalog = ContainmentConformanceSuiteCatalog.from_dict(conformance_catalog.to_dict())
    verified_report = BackendConformanceReport.from_dict(
        conformance_report.to_dict(), attestation, verified_catalog
    )
    verified_admission = BackendAdmissionReceipt.from_dict(
        backend_admission.to_dict(),
        verified_report,
        attestation,
        manifest,
        verified_catalog,
    )
    submission = verified_evidence.submission.to_dict()
    packet = verified_evidence.packet.manifest
    if (
        verified_catalog != conformance_catalog
        or verified_report != conformance_report
        or verified_admission != backend_admission
        or verified_evidence.backend_admission_sha256 != backend_admission.admission_sha256
        or submission.get("backend_admission_sha256") != backend_admission.admission_sha256
        or submission.get("manifest_sha256") != manifest.manifest_sha256
        or submission.get("profile_id") != manifest.profile_id
        or submission.get("vector_id") != manifest.vector_id
        or packet.get("manifest_sha256") != manifest.manifest_sha256
        or verified_evidence.plan.manifest_sha256 != manifest.manifest_sha256
        or verified_evidence.plan.backend_attestation_sha256 != attestation.attestation_sha256
    ):
        raise QualificationError("Verified Phase 157 evidence is not bound to admission inputs")


@dataclass(frozen=True)
class Phase158AdmissionHandoff:
    handoff_id: str
    handoff_sha256: str
    profile_id: str
    manifest_sha256: str
    evidence_submission_sha256: str
    status: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        *,
        manifest: AdapterManifest,
        adapter_catalog: CandidateAdapterCatalog,
        development_gates: CandidateDevelopmentGateCatalog,
        qualification_plans: QualificationPlanCatalogV2,
        registry: ExpertRegistry,
        capabilities: CapabilityCatalog,
        vectors: AttackVectorCatalog,
        roadmap: ArmyExpansionRoadmap,
        standard: QualificationStandard,
        verified_evidence: VerifiedCandidateExecutionEvidence,
        backend_admission: BackendAdmissionReceipt,
        attestation: ContainmentBackendAttestation,
        conformance_catalog: ContainmentConformanceSuiteCatalog,
        conformance_report: BackendConformanceReport,
    ) -> Phase158AdmissionHandoff:
        expected_fields = {
            "schema_version",
            "handoff_id",
            "handoff_sha256",
            "adapter_id",
            "adapter_catalog_sha256",
            "profile_id",
            "vector_id",
            "manifest_sha256",
            "development_gate_catalog_sha256",
            "development_gate_sha256",
            "containment_gate_resolution",
            "qualification_plan_catalog_sha256",
            "qualification_plan_entry_sha256",
            "qualification_plan_entry",
            "backend_admission_id",
            "backend_admission_sha256",
            "backend_attestation_sha256",
            "conformance_report_sha256",
            "evidence_submission_id",
            "evidence_submission_sha256",
            "evidence_packet_sha256",
            "execution_plan_sha256",
            "execution_receipt_sha256",
            "result_sha256",
            "domain_commander_id",
            "domain_commander_profile_sha256",
            "independent_validator_id",
            "independent_validator_profile_sha256",
            "required_scenario_variant_count",
            "required_gate_count",
            "minimum_distinct_evaluators",
            "required_review_roles",
            "review_requirement",
            "prepared_at",
            "status",
            *EFFECT_FIELDS,
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise QualificationError("Phase 158 admission handoff fields are invalid")
        static = _validate_static_bindings(
            manifest=manifest,
            adapter_catalog=adapter_catalog,
            development_gates=development_gates,
            qualification_plans=qualification_plans,
            registry=registry,
            capabilities=capabilities,
            vectors=vectors,
            roadmap=roadmap,
            standard=standard,
        )
        _validate_dynamic_bindings(
            manifest=manifest,
            verified_evidence=verified_evidence,
            backend_admission=backend_admission,
            attestation=attestation,
            conformance_catalog=conformance_catalog,
            conformance_report=conformance_report,
        )
        admission = backend_admission.to_dict()
        report = conformance_report.to_dict()
        expected_bindings = {
            "schema_version": 1,
            "adapter_id": manifest.adapter_id,
            "adapter_catalog_sha256": adapter_catalog.catalog_sha256,
            "profile_id": manifest.profile_id,
            "vector_id": manifest.vector_id,
            "manifest_sha256": manifest.manifest_sha256,
            "development_gate_catalog_sha256": development_gates.catalog_sha256,
            "development_gate_sha256": list(static.gate_sha256),
            "containment_gate_resolution": (
                "resolved_by_verified_phase157_candidate_execution_evidence"
            ),
            "qualification_plan_catalog_sha256": qualification_plans.catalog_sha256,
            "qualification_plan_entry_sha256": static.plan_sha256,
            "qualification_plan_entry": static.plan,
            "backend_admission_id": backend_admission.admission_id,
            "backend_admission_sha256": backend_admission.admission_sha256,
            "backend_attestation_sha256": attestation.attestation_sha256,
            "conformance_report_sha256": report["report_sha256"],
            "evidence_submission_id": verified_evidence.submission.submission_id,
            "evidence_submission_sha256": verified_evidence.submission.submission_sha256,
            "evidence_packet_sha256": verified_evidence.packet.packet_sha256,
            "execution_plan_sha256": verified_evidence.plan.plan_sha256,
            "execution_receipt_sha256": verified_evidence.receipt.receipt_sha256,
            "result_sha256": verified_evidence.result.result_sha256,
            "domain_commander_id": static.commander_id,
            "domain_commander_profile_sha256": static.commander_sha256,
            "independent_validator_id": static.validator_id,
            "independent_validator_profile_sha256": static.validator_sha256,
            "required_scenario_variant_count": len(static.plan["required_scenario_variants"]),
            "required_gate_count": len(static.plan["required_gate_ids"]),
            "minimum_distinct_evaluators": standard.decision_policy.minimum_distinct_evaluators,
            "required_review_roles": [
                "domain_commander",
                "independent_control",
                "independent_assurance",
            ],
            "review_requirement": "execute_plan_then_commander_control_assurance_review",
            "status": "prepared_for_phase158_evaluation",
        }
        if (
            any(raw.get(key) != value for key, value in expected_bindings.items())
            or any(raw.get(field) != "none" for field in EFFECT_FIELDS)
            or admission.get("status") != "admitted_for_phase157_synthetic_only"
        ):
            raise QualificationError("Phase 158 admission handoff binding is invalid")
        _utc(raw.get("prepared_at"), "Phase 158 handoff prepared_at")
        handoff_id, digest = _content_identity(
            raw,
            domain=HANDOFF_DOMAIN,
            id_field="handoff_id",
            hash_field="handoff_sha256",
            prefix="PAH",
            pattern=HANDOFF_ID_PATTERN,
        )
        return cls(
            handoff_id,
            digest,
            manifest.profile_id,
            manifest.manifest_sha256,
            verified_evidence.submission.submission_sha256,
            "prepared_for_phase158_evaluation",
            _canonical_json(raw),
        )


def build_phase158_admission_handoff(
    *,
    manifest: AdapterManifest,
    adapter_catalog: CandidateAdapterCatalog,
    development_gates: CandidateDevelopmentGateCatalog,
    qualification_plans: QualificationPlanCatalogV2,
    registry: ExpertRegistry,
    capabilities: CapabilityCatalog,
    vectors: AttackVectorCatalog,
    roadmap: ArmyExpansionRoadmap,
    standard: QualificationStandard,
    verified_evidence: VerifiedCandidateExecutionEvidence,
    backend_admission: BackendAdmissionReceipt,
    attestation: ContainmentBackendAttestation,
    conformance_catalog: ContainmentConformanceSuiteCatalog,
    conformance_report: BackendConformanceReport,
    prepared_at: str,
) -> Phase158AdmissionHandoff:
    static = _validate_static_bindings(
        manifest=manifest,
        adapter_catalog=adapter_catalog,
        development_gates=development_gates,
        qualification_plans=qualification_plans,
        registry=registry,
        capabilities=capabilities,
        vectors=vectors,
        roadmap=roadmap,
        standard=standard,
    )
    _validate_dynamic_bindings(
        manifest=manifest,
        verified_evidence=verified_evidence,
        backend_admission=backend_admission,
        attestation=attestation,
        conformance_catalog=conformance_catalog,
        conformance_report=conformance_report,
    )
    body = {
        "schema_version": 1,
        "adapter_id": manifest.adapter_id,
        "adapter_catalog_sha256": adapter_catalog.catalog_sha256,
        "profile_id": manifest.profile_id,
        "vector_id": manifest.vector_id,
        "manifest_sha256": manifest.manifest_sha256,
        "development_gate_catalog_sha256": development_gates.catalog_sha256,
        "development_gate_sha256": list(static.gate_sha256),
        "containment_gate_resolution": (
            "resolved_by_verified_phase157_candidate_execution_evidence"
        ),
        "qualification_plan_catalog_sha256": qualification_plans.catalog_sha256,
        "qualification_plan_entry_sha256": static.plan_sha256,
        "qualification_plan_entry": static.plan,
        "backend_admission_id": backend_admission.admission_id,
        "backend_admission_sha256": backend_admission.admission_sha256,
        "backend_attestation_sha256": attestation.attestation_sha256,
        "conformance_report_sha256": conformance_report.report_sha256,
        "evidence_submission_id": verified_evidence.submission.submission_id,
        "evidence_submission_sha256": verified_evidence.submission.submission_sha256,
        "evidence_packet_sha256": verified_evidence.packet.packet_sha256,
        "execution_plan_sha256": verified_evidence.plan.plan_sha256,
        "execution_receipt_sha256": verified_evidence.receipt.receipt_sha256,
        "result_sha256": verified_evidence.result.result_sha256,
        "domain_commander_id": static.commander_id,
        "domain_commander_profile_sha256": static.commander_sha256,
        "independent_validator_id": static.validator_id,
        "independent_validator_profile_sha256": static.validator_sha256,
        "required_scenario_variant_count": len(static.plan["required_scenario_variants"]),
        "required_gate_count": len(static.plan["required_gate_ids"]),
        "minimum_distinct_evaluators": standard.decision_policy.minimum_distinct_evaluators,
        "required_review_roles": [
            "domain_commander",
            "independent_control",
            "independent_assurance",
        ],
        "review_requirement": "execute_plan_then_commander_control_assurance_review",
        "prepared_at": prepared_at,
        "status": "prepared_for_phase158_evaluation",
        **{field: "none" for field in EFFECT_FIELDS},
    }
    digest = _canonical_sha256({"domain": HANDOFF_DOMAIN, "document": body})
    document = {
        **body,
        "handoff_id": f"PAH-{digest.removeprefix('sha256:')[:32].upper()}",
        "handoff_sha256": digest,
    }
    return Phase158AdmissionHandoff.from_dict(
        document,
        manifest=manifest,
        adapter_catalog=adapter_catalog,
        development_gates=development_gates,
        qualification_plans=qualification_plans,
        registry=registry,
        capabilities=capabilities,
        vectors=vectors,
        roadmap=roadmap,
        standard=standard,
        verified_evidence=verified_evidence,
        backend_admission=backend_admission,
        attestation=attestation,
        conformance_catalog=conformance_catalog,
        conformance_report=conformance_report,
    )


@dataclass(frozen=True)
class Phase158AdmissionBlockerAssessment:
    assessment_id: str
    assessment_sha256: str
    profile_id: str
    blockers: tuple[str, ...]
    status: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        *,
        manifest: AdapterManifest,
        adapter_catalog: CandidateAdapterCatalog,
        development_gates: CandidateDevelopmentGateCatalog,
        qualification_plans: QualificationPlanCatalogV2,
        registry: ExpertRegistry,
        capabilities: CapabilityCatalog,
        vectors: AttackVectorCatalog,
        roadmap: ArmyExpansionRoadmap,
        standard: QualificationStandard,
    ) -> Phase158AdmissionBlockerAssessment:
        expected_fields = {
            "schema_version",
            "assessment_id",
            "assessment_sha256",
            "adapter_id",
            "adapter_catalog_sha256",
            "profile_id",
            "vector_id",
            "manifest_sha256",
            "development_gate_catalog_sha256",
            "qualification_plan_catalog_sha256",
            "qualification_plan_entry_sha256",
            "domain_commander_id",
            "independent_validator_id",
            "blockers",
            "status",
            *EFFECT_FIELDS,
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise QualificationError("Phase 158 blocker assessment fields are invalid")
        static = _validate_static_bindings(
            manifest=manifest,
            adapter_catalog=adapter_catalog,
            development_gates=development_gates,
            qualification_plans=qualification_plans,
            registry=registry,
            capabilities=capabilities,
            vectors=vectors,
            roadmap=roadmap,
            standard=standard,
        )
        expected_bindings = {
            "schema_version": 1,
            "adapter_id": manifest.adapter_id,
            "adapter_catalog_sha256": adapter_catalog.catalog_sha256,
            "profile_id": manifest.profile_id,
            "vector_id": manifest.vector_id,
            "manifest_sha256": manifest.manifest_sha256,
            "development_gate_catalog_sha256": development_gates.catalog_sha256,
            "qualification_plan_catalog_sha256": qualification_plans.catalog_sha256,
            "qualification_plan_entry_sha256": static.plan_sha256,
            "domain_commander_id": static.commander_id,
            "independent_validator_id": static.validator_id,
            "blockers": list(CURRENT_BLOCKERS),
            "status": "blocked_pending_external_phase157_evidence",
        }
        if any(raw.get(key) != value for key, value in expected_bindings.items()) or any(
            raw.get(field) != "none" for field in EFFECT_FIELDS
        ):
            raise QualificationError("Phase 158 blocker assessment binding is invalid")
        assessment_id, digest = _content_identity(
            raw,
            domain=BLOCKER_DOMAIN,
            id_field="assessment_id",
            hash_field="assessment_sha256",
            prefix="PAB",
            pattern=ASSESSMENT_ID_PATTERN,
        )
        return cls(
            assessment_id,
            digest,
            manifest.profile_id,
            CURRENT_BLOCKERS,
            "blocked_pending_external_phase157_evidence",
            _canonical_json(raw),
        )


def assess_phase158_admission_blockers(
    *,
    manifest: AdapterManifest,
    adapter_catalog: CandidateAdapterCatalog,
    development_gates: CandidateDevelopmentGateCatalog,
    qualification_plans: QualificationPlanCatalogV2,
    registry: ExpertRegistry,
    capabilities: CapabilityCatalog,
    vectors: AttackVectorCatalog,
    roadmap: ArmyExpansionRoadmap,
    standard: QualificationStandard,
) -> Phase158AdmissionBlockerAssessment:
    static = _validate_static_bindings(
        manifest=manifest,
        adapter_catalog=adapter_catalog,
        development_gates=development_gates,
        qualification_plans=qualification_plans,
        registry=registry,
        capabilities=capabilities,
        vectors=vectors,
        roadmap=roadmap,
        standard=standard,
    )
    body = {
        "schema_version": 1,
        "adapter_id": manifest.adapter_id,
        "adapter_catalog_sha256": adapter_catalog.catalog_sha256,
        "profile_id": manifest.profile_id,
        "vector_id": manifest.vector_id,
        "manifest_sha256": manifest.manifest_sha256,
        "development_gate_catalog_sha256": development_gates.catalog_sha256,
        "qualification_plan_catalog_sha256": qualification_plans.catalog_sha256,
        "qualification_plan_entry_sha256": static.plan_sha256,
        "domain_commander_id": static.commander_id,
        "independent_validator_id": static.validator_id,
        "blockers": list(CURRENT_BLOCKERS),
        "status": "blocked_pending_external_phase157_evidence",
        **{field: "none" for field in EFFECT_FIELDS},
    }
    digest = _canonical_sha256({"domain": BLOCKER_DOMAIN, "document": body})
    document = {
        **body,
        "assessment_id": f"PAB-{digest.removeprefix('sha256:')[:32].upper()}",
        "assessment_sha256": digest,
    }
    return Phase158AdmissionBlockerAssessment.from_dict(
        document,
        manifest=manifest,
        adapter_catalog=adapter_catalog,
        development_gates=development_gates,
        qualification_plans=qualification_plans,
        registry=registry,
        capabilities=capabilities,
        vectors=vectors,
        roadmap=roadmap,
        standard=standard,
    )


__all__ = [
    "Phase158AdmissionBlockerAssessment",
    "Phase158AdmissionHandoff",
    "assess_phase158_admission_blockers",
    "build_phase158_admission_handoff",
]
