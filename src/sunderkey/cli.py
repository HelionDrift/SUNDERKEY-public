"""Command line entry points for registry and mission validation."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from .agent_trace_regression import (
    MAX_COMPARISON_BYTES as MAX_AGENT_TRACE_COMPARISON_BYTES,
)
from .agent_trace_regression import (
    AgentTraceRegressionError,
    build_agent_trace_regression,
    verify_agent_trace_regression,
)
from .agent_trace_review import (
    MAX_INPUT_BYTES as MAX_AGENT_TRACE_BYTES,
)
from .agent_trace_review import (
    MAX_REVIEW_BYTES as MAX_AGENT_TRACE_REVIEW_BYTES,
)
from .agent_trace_review import (
    AgentTraceReviewError,
    build_agent_trace_review,
    verify_agent_trace_review,
)
from .approvals import ApprovalService, ApprovalState
from .army_readiness import assess_army_readiness
from .authenticated import AuthenticatedMissionControlService
from .authenticated_approval_revocations import (
    AuthenticatedApprovalRevocationService,
)
from .authenticated_approvals import AuthenticatedApprovalDecisionService
from .authenticated_collaboration import (
    AuthenticatedCollaborationActivationService,
)
from .authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from .authenticated_collaboration_ownership import (
    AuthenticatedCollaborationOwnershipService,
)
from .authenticated_collaboration_ownership_privileged_reassignment import (
    AuthenticatedCollaborationOwnershipPrivilegedReassignmentService,
)
from .authenticated_collaboration_ownership_revocation import (
    AuthenticatedCollaborationOwnershipRevocationService,
)
from .authenticated_events import AuthenticatedEventAppendService
from .authenticated_missions import (
    AuthenticatedMissionCreationService,
)
from .authenticated_provider_evidence_repository import (
    read_provider_evidence_repository_ingest_authentication,
)
from .authenticated_simulations import AuthenticatedSimulationService
from .authenticated_submissions import AuthenticatedApprovalSubmissionService
from .authenticated_work import AuthenticatedWorkItemLeaseService
from .authenticated_work_cancellations import (
    AuthenticatedWorkCancellationService,
)
from .authenticated_work_handoffs import (
    AuthenticatedWorkHandoffService,
)
from .authenticated_work_recovery import (
    AuthenticatedWorkRecoveryService,
)
from .candidate_blueprints import (
    assess_candidate_blueprint_coverage,
    load_candidate_blueprint_catalog,
)
from .candidate_components import (
    assess_candidate_onboarding,
    load_candidate_component_catalog,
)
from .candidate_enrollment import (
    load_candidate_enrollment_catalog,
    load_candidate_enrollment_signer_authorization,
)
from .candidate_enrollment_activation_decision import (
    build_candidate_enrollment_activation_decision_submission_template,
    load_candidate_enrollment_activation_decision_record,
    load_candidate_enrollment_activation_decision_submission,
    record_candidate_enrollment_activation_decision,
    verify_candidate_enrollment_activation_decision_record,
)
from .candidate_enrollment_activation_dossier import (
    build_candidate_enrollment_activation_decision_dossier,
    load_candidate_enrollment_activation_decision_dossier,
)
from .candidate_enrollment_activation_implementation import (
    build_candidate_enrollment_activation_implementation_report,
    load_candidate_enrollment_activation_implementation_report,
)
from .candidate_enrollment_canary import (
    build_candidate_enrollment_canary_preparation,
    load_candidate_enrollment_canary_preparation,
)
from .candidate_enrollment_decision import (
    build_candidate_enrollment_decision_submission_template,
    load_candidate_enrollment_decision_record,
    load_candidate_enrollment_decision_submission,
    record_candidate_enrollment_decision,
    verify_candidate_enrollment_decision_record,
)
from .candidate_enrollment_deployment import (
    build_candidate_enrollment_deployment_preparation,
    load_candidate_enrollment_deployment_preparation,
)
from .candidate_enrollment_deployment_inputs import (
    assess_candidate_enrollment_deployment_inputs,
    build_candidate_enrollment_deployment_worksheet,
    load_candidate_enrollment_deployment_preflight,
    load_candidate_enrollment_deployment_worksheet,
)
from .candidate_enrollment_deployment_verification import (
    load_candidate_enrollment_deployment_verification_context,
    load_candidate_enrollment_deployment_verification_receipt,
    verify_candidate_enrollment_deployment_artifacts,
    verify_candidate_enrollment_deployment_verification_receipt,
)
from .candidate_enrollment_dossier import (
    assess_candidate_enrollment_decision,
    load_candidate_enrollment_decision_dossier,
)
from .candidate_enrollment_implementation import (
    load_candidate_enrollment_implementation_report,
)
from .candidate_enrollment_production_custody_decision import (
    build_candidate_enrollment_production_custody_decision_submission_template,
    load_candidate_enrollment_production_custody_decision_record,
    load_candidate_enrollment_production_custody_decision_submission,
    record_candidate_enrollment_production_custody_decision,
    verify_candidate_enrollment_production_custody_decision_record,
)
from .candidate_enrollment_production_custody_dossier import (
    build_candidate_enrollment_production_custody_dossier,
    load_candidate_enrollment_production_custody_dossier,
)
from .candidate_enrollment_release_contract import (
    build_candidate_enrollment_release_policy,
    load_candidate_enrollment_release_policy,
)
from .candidate_inventory import (
    assess_candidate_inventory,
    load_candidate_implementation_catalog,
)
from .candidate_preflight import (
    assess_candidate_evaluation_preflight,
    load_candidate_evaluation_submission,
    load_candidate_onboarding_report,
)
from .capability_roadmap import (
    assess_capability_roadmap,
    load_capability_roadmap,
)
from .collaboration import (
    build_collaboration_plan,
    load_collaboration_plan,
)
from .collaboration_authority_decision import (
    build_collaboration_authority_decision_submission_template,
    load_collaboration_authority_decision_record,
    load_collaboration_authority_decision_submission,
    record_collaboration_authority_decision,
    verify_collaboration_authority_decision_record,
)
from .collaboration_authority_dossier import (
    assess_collaboration_authority_decisions,
    load_collaboration_authority_decision_dossier,
)
from .collaboration_mission_policy import (
    load_collaboration_mission_reconfiguration_policy,
)
from .collaboration_ownership_chain import (
    load_collaboration_ownership_chain_entry,
    load_collaboration_ownership_revocation,
)
from .collaboration_ownership_preflight import (
    CollaborationOwnershipTransitionPreflightService,
    load_collaboration_ownership_transition_preflight,
)
from .collaboration_ownership_privileged_reassignment_preflight import (
    CollaborationOwnershipPrivilegedReassignmentPreflightService,
    load_collaboration_ownership_privileged_reassignment_preflight,
)
from .collaboration_ownership_revocation_preflight import (
    CollaborationOwnershipRevocationPreflightService,
    load_collaboration_ownership_revocation_preflight,
)
from .collaboration_plan_replacement_operations import (
    CollaborationPlanReplacementOperationsService,
    load_collaboration_plan_replacement_credentials,
    load_collaboration_plan_replacement_mapping_intents,
    load_prepared_collaboration_plan_replacement,
)
from .collaboration_reconfiguration_policy import (
    build_collaboration_reconfiguration_authority_policy,
    load_collaboration_reconfiguration_authority_policy,
)
from .content_guard import require_clean_repository_text
from .errors import SunderkeyError
from .events import EventLedger, MissionEvent
from .identity import (
    load_principal_assertion,
    load_principal_trust_policy,
    load_scope_grant,
    load_scope_grant_revocation,
)
from .implementation_roadmap import (
    assess_specialist_implementation_roadmap,
    load_specialist_implementation_roadmap,
)
from .implementation_work_packages import (
    assess_implementation_work_packages,
    load_implementation_work_package_report,
    select_implementation_wave_package,
)
from .mcp_api_read_bindings import (
    MAX_BINDINGS_BYTES as MAX_MCP_BINDINGS_BYTES,
)
from .mcp_api_read_bindings import (
    MAX_PLAN_BYTES as MAX_MCP_BINDING_PLAN_BYTES,
)
from .mcp_api_read_bindings import (
    MCPApiReadBindingError,
    build_mcp_api_read_bindings,
    verify_mcp_api_read_bindings,
)
from .mcp_catalog_preflight import (
    MAX_INPUT_BYTES as MAX_MCP_CATALOG_BYTES,
)
from .mcp_catalog_preflight import (
    MAX_PREFLIGHT_BYTES as MAX_MCP_PREFLIGHT_BYTES,
)
from .mcp_catalog_preflight import (
    MCPCatalogPreflightError,
    build_mcp_catalog_preflight,
    verify_mcp_catalog_preflight,
)
from .mcp_schema_byte_preflight import (
    MAX_BUNDLE_BYTES as MAX_MCP_SCHEMA_BUNDLE_BYTES,
    MAX_RESULT_BYTES as MAX_MCP_SCHEMA_RESULT_BYTES,
    MCPSchemaBytePreflightError,
    build_mcp_schema_byte_preflight,
    verify_mcp_schema_byte_preflight,
)
from .mcp_schema_semantic_preflight import (
    MCPSchemaSemanticPreflightError,
    build_mcp_schema_semantic_preflight,
    verify_mcp_schema_semantic_preflight,
)
from .mcp_header_annotation_preflight import (
    MCPHeaderAnnotationPreflightError,
    build_mcp_header_annotation_preflight,
    verify_mcp_header_annotation_preflight,
)
from .mission import assemble_joint_mission_cell, load_mission_request
from .mission_audit import MissionAuditSnapshotService
from .mission_control import (
    MissionControlService,
    MissionStopReason,
)
from .offline_review_handoff import (
    MAX_HANDOFF_BYTES,
    OfflineReviewHandoffError,
    build_offline_review_handoff,
    verify_offline_review_handoff,
)
from .offline_review_transition import (
    MAX_TRANSITION_BYTES,
    OfflineReviewTransitionError,
    build_offline_review_transition,
    verify_offline_review_transition,
)
from .offline_review_workflow import (
    MAX_BUNDLE_BYTES,
    MAX_INPUT_BYTES,
    OfflineReviewWorkflowError,
    build_offline_review_bundle,
    verify_offline_review_bundle,
)
from .plan_replacement_reviewer_admission import (
    REVIEWER_OPERATIONS,
    AuthenticatedPlanReplacementReviewerAdmissionService,
    load_plan_replacement_reviewer_admission_request,
)
from .plan_replacement_reviewer_admission_intents import (
    build_plan_replacement_reviewer_admission_approval_intents,
)
from .qualification import (
    assess_qualification_coverage,
    load_qualification_plan_catalog,
    load_qualification_standard,
)
from .qualification_authority_decision import (
    load_qualification_authority_decision_record,
    record_qualification_authority_decision,
)
from .qualification_authority_dossier import (
    QualificationAuthorityDecisionDossier,
    assess_qualification_authority_decision,
)
from .qualification_evaluation import (
    evaluate_qualification_observations,
    load_qualification_evaluation_suite,
    load_qualification_observation_set,
)
from .qualification_trust import (
    load_qualification_reviewer_credential,
    load_qualification_trust_policy,
)
from .registry import load_registry
from .remediation_case_review import NO_EFFECTS as REMEDIATION_CASE_NO_EFFECTS
from .remediation_case_review_io import (
    build_remediation_case_review_from_request,
    load_remediation_case_request,
    load_remediation_case_review,
    serialize_remediation_case_review,
    verify_remediation_case_review_from_request,
)
from .remediation_validation_contracts import RemediationValidationError
from .routing import (
    load_capability_catalog,
    load_routing_policy,
    load_routing_request,
    route_mission,
)
from .scope import (
    ScopeGrantAcceptanceService,
    ScopeGrantRevocationAcceptanceService,
)
from .service_contract_extractor import (
    ServiceContractEndpointBundle,
    ServiceContractExtractionError,
)
from .simulation import SimulationService
from .store import MissionStore
from .traffic_derived_api_inventory import (
    MAX_INVENTORY_JSON_BYTES,
    MAX_OBSERVATIONS,
    SanitizedApiTrafficObservation,
    TrafficApiInventoryError,
    load_traffic_api_inventory_json,
    verify_traffic_api_inventory_from_sources,
)
from .trust import TrustProvisioningService
from .validation import loads_json_without_duplicate_keys

RAW_PUBLIC_KEY_PATTERN = re.compile(r"[-_A-Za-z0-9]{43}")


def _normalized_argument_tokens(arguments: list[str]) -> list[str]:
    normalized: list[str] = []
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if (
            token == "--root-public-key"
            and index + 1 < len(arguments)
            and RAW_PUBLIC_KEY_PATTERN.fullmatch(arguments[index + 1])
            is not None
        ):
            normalized.append(f"{token}={arguments[index + 1]}")
            index += 2
            continue
        normalized.append(token)
        index += 1
    return normalized


class _SunderkeyArgumentParser(argparse.ArgumentParser):
    def parse_args(
        self,
        args: list[str] | None = None,
        namespace: argparse.Namespace | None = None,
    ) -> argparse.Namespace:
        arguments = sys.argv[1:] if args is None else list(args)
        return super().parse_args(
            _normalized_argument_tokens(arguments),
            namespace,
        )


def _resolved_argument_path(
    args: argparse.Namespace,
    attribute: str,
) -> Path | None:
    value = getattr(args, attribute, None)
    if value is None:
        return None
    try:
        return Path(value).resolve()
    except OSError as exc:
        raise SunderkeyError(
            f"Could not resolve --{attribute.replace('_', '-')}: {value}"
        ) from exc


def _validate_write_path_collisions(args: argparse.Namespace) -> None:
    output_attributes = (
        "output",
        "mission_output",
        "destination",
        "backup_destination",
    )
    protected_attributes = (
        "registry",
        "mission",
        "events",
        "capabilities",
        "policy",
        "standard",
        "plans",
        "blueprints",
        "components",
        "candidates",
        "roadmap",
        "packages",
        "dossier",
        "authority_decision",
        "onboarding",
        "suite",
        "submission",
        "observations",
        "binding",
        "instructions",
        "scenarios",
        "receipt",
        "review",
        "smoke_receipt",
        "smoke_review",
        "directory",
        "pack_directory",
        "packet",
        "control_review",
        "assurance_review",
        "comparison",
        "reconciliation",
        "control_reconciliation",
        "assurance_reconciliation",
        "alignment",
        "preflight",
        "source_preflight",
        "complete_preflight",
        "smoke_packet",
        "smoke_control_review",
        "smoke_assurance_review",
        "smoke_comparison",
        "smoke_control_reconciliation",
        "smoke_assurance_reconciliation",
        "smoke_alignment",
        "request",
        "principal_assertion",
        "authority_policy",
        "mission_policy",
        "replacement_plan",
        "mapping_intents",
        "preparation",
        "credentials",
        "mission_owner_assertion",
        "current_owner_assertion",
        "proposed_owner_assertion",
        "planned_owner_assertion",
        "independent_control_assertion",
        "second_authority_assertion",
        "ownership_entry",
        "revocation",
        "scope_grant",
        "scope_grant_revocation",
        "store",
        "root",
    )
    outputs = {
        attribute: path
        for attribute in output_attributes
        if (path := _resolved_argument_path(args, attribute)) is not None
    }
    if not outputs:
        return
    protected = {
        attribute: path
        for attribute in protected_attributes
        if (path := _resolved_argument_path(args, attribute)) is not None
    }
    output_items = tuple(outputs.items())
    for index, (attribute, path) in enumerate(output_items):
        for other_attribute, other_path in output_items[index + 1 :]:
            if _paths_alias(path, other_path):
                raise SunderkeyError(
                    f"--{attribute.replace('_', '-')} and "
                    f"--{other_attribute.replace('_', '-')} must differ"
                )
        for protected_attribute, protected_path in protected.items():
            if _paths_alias(path, protected_path):
                raise SunderkeyError(
                    f"--{attribute.replace('_', '-')} must not replace "
                    f"--{protected_attribute.replace('_', '-')}"
                )


def _paths_alias(left: Path, right: Path) -> bool:
    if left == right:
        return True
    try:
        return left.exists() and right.exists() and left.samefile(right)
    except OSError as exc:
        raise SunderkeyError(
            f"Could not compare output paths: {left} and {right}"
        ) from exc


def _write_json(value: Any, output: str | None) -> None:
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if output is None:
        print(text, end="")
        return
    path = Path(os.path.abspath(output))
    temporary_path: Path | None = None
    descriptor: int | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        stream = os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        )
        descriptor = None
        with stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    except OSError as exc:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        if temporary_path is not None:
            with suppress(OSError):
                temporary_path.unlink(missing_ok=True)
        raise SunderkeyError(
            f"Could not write JSON output: {path}"
        ) from exc


def _require_new_output_path(output: str) -> Path:
    path = Path(os.path.abspath(output))
    if os.path.lexists(path):
        raise SunderkeyError(f"Output already exists: {path}")
    return path


def _write_json_exclusive(value: Any, output: str) -> None:
    """Publish JSON through an exclusive same-directory hard link."""

    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    path = _require_new_output_path(output)
    temporary_path: Path | None = None
    descriptor: int | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        stream = os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        )
        descriptor = None
        with stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary_path, path)
        temporary_path.unlink()
        temporary_path = None
    except FileExistsError as exc:
        raise SunderkeyError(f"Output already exists: {path}") from exc
    except OSError as exc:
        raise SunderkeyError(f"Could not write JSON output: {path}") from exc
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        if temporary_path is not None:
            with suppress(OSError):
                temporary_path.unlink(missing_ok=True)


def _read_events(path_value: str) -> tuple[MissionEvent, ...]:
    path = Path(path_value).resolve()
    if not path.is_file():
        raise SunderkeyError(f"Event file does not exist: {path}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise SunderkeyError(
            f"Could not read event file as UTF-8 text: {path}"
        ) from exc
    events: list[MissionEvent] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            raw = loads_json_without_duplicate_keys(line)
        except (json.JSONDecodeError, ValueError) as exc:
            raise SunderkeyError(
                f"Invalid JSON on event line {line_number}"
            ) from exc
        events.append(MissionEvent.from_dict(raw))
    if not events:
        raise SunderkeyError("Event file must contain at least one event")
    return tuple(events)


def _validate_registry(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    counts = {
        "catalog_id": registry.catalog_id,
        "catalog_version": registry.catalog_version,
        "groups": len(registry.groups),
        "commands": len(registry.commands),
        "profiles": len(registry.profiles),
        "pilot_specialists": registry.count_contract.pilot_specialists,
    }
    _write_json(counts, args.output)


def _assess_army_readiness(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    catalog = load_capability_catalog(
        args.capabilities,
        registry,
    )
    policy = load_routing_policy(args.policy, catalog)
    report = assess_army_readiness(registry, catalog, policy)
    _write_json(report.to_dict(), args.output)


def _assess_qualification_coverage(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    catalog = load_capability_catalog(args.capabilities, registry)
    standard = load_qualification_standard(
        args.standard,
        registry,
        catalog,
    )
    plans = load_qualification_plan_catalog(
        args.plans,
        registry,
        catalog,
        standard,
    )
    report = assess_qualification_coverage(
        registry,
        catalog,
        standard,
        plans,
    )
    _write_json(report.to_dict(), args.output)


def _evaluate_qualification(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    catalog = load_capability_catalog(args.capabilities, registry)
    standard = load_qualification_standard(
        args.standard,
        registry,
        catalog,
    )
    plans = load_qualification_plan_catalog(
        args.plans,
        registry,
        catalog,
        standard,
    )
    suite = load_qualification_evaluation_suite(
        args.suite,
        registry,
        catalog,
        standard,
        plans,
    )
    observations = load_qualification_observation_set(
        args.observations,
        suite,
    )
    report = evaluate_qualification_observations(
        registry,
        catalog,
        standard,
        plans,
        suite,
        observations,
    )
    _write_json(report.to_dict(), args.output)


def _assess_candidate_inventory(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    catalog = load_capability_catalog(args.capabilities, registry)
    standard = load_qualification_standard(
        args.standard,
        registry,
        catalog,
    )
    plans = load_qualification_plan_catalog(
        args.plans,
        registry,
        catalog,
        standard,
    )
    blueprints = load_candidate_blueprint_catalog(
        args.blueprints,
        registry,
        catalog,
        standard,
        plans,
    )
    candidates = load_candidate_implementation_catalog(
        args.candidates,
        registry,
        catalog,
        standard,
        plans,
        blueprints,
    )
    report = assess_candidate_inventory(
        registry,
        catalog,
        standard,
        plans,
        blueprints,
        candidates,
    )
    _write_json(report.to_dict(), args.output)


def _assess_candidate_blueprint_coverage(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    catalog = load_capability_catalog(args.capabilities, registry)
    standard = load_qualification_standard(
        args.standard,
        registry,
        catalog,
    )
    plans = load_qualification_plan_catalog(
        args.plans,
        registry,
        catalog,
        standard,
    )
    blueprints = load_candidate_blueprint_catalog(
        args.blueprints,
        registry,
        catalog,
        standard,
        plans,
    )
    report = assess_candidate_blueprint_coverage(
        registry,
        catalog,
        standard,
        plans,
        blueprints,
    )
    _write_json(report.to_dict(), args.output)


def _assess_candidate_onboarding(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    catalog = load_capability_catalog(args.capabilities, registry)
    standard = load_qualification_standard(
        args.standard,
        registry,
        catalog,
    )
    plans = load_qualification_plan_catalog(
        args.plans,
        registry,
        catalog,
        standard,
    )
    blueprints = load_candidate_blueprint_catalog(
        args.blueprints,
        registry,
        catalog,
        standard,
        plans,
    )
    components = load_candidate_component_catalog(
        args.components,
        blueprints,
    )
    candidates = load_candidate_implementation_catalog(
        args.candidates,
        registry,
        catalog,
        standard,
        plans,
        blueprints,
    )
    report = assess_candidate_onboarding(
        registry,
        catalog,
        standard,
        plans,
        blueprints,
        components,
        candidates,
    )
    _write_json(report.to_dict(), args.output)


def _assess_candidate_evaluation_preflight(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    catalog = load_capability_catalog(args.capabilities, registry)
    standard = load_qualification_standard(
        args.standard,
        registry,
        catalog,
    )
    plans = load_qualification_plan_catalog(
        args.plans,
        registry,
        catalog,
        standard,
    )
    blueprints = load_candidate_blueprint_catalog(
        args.blueprints,
        registry,
        catalog,
        standard,
        plans,
    )
    components = load_candidate_component_catalog(
        args.components,
        blueprints,
    )
    candidates = load_candidate_implementation_catalog(
        args.candidates,
        registry,
        catalog,
        standard,
        plans,
        blueprints,
    )
    onboarding = load_candidate_onboarding_report(args.onboarding)
    suite = load_qualification_evaluation_suite(
        args.suite,
        registry,
        catalog,
        standard,
        plans,
    )
    submission = load_candidate_evaluation_submission(args.submission)
    report = assess_candidate_evaluation_preflight(
        registry,
        catalog,
        standard,
        plans,
        blueprints,
        components,
        candidates,
        onboarding,
        suite,
        submission,
    )
    _write_json(report.to_dict(), args.output)


def _assess_specialist_implementation_roadmap(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    catalog = load_capability_catalog(args.capabilities, registry)
    policy = load_routing_policy(args.policy, catalog)
    standard = load_qualification_standard(
        args.standard,
        registry,
        catalog,
    )
    plans = load_qualification_plan_catalog(
        args.plans,
        registry,
        catalog,
        standard,
    )
    blueprints = load_candidate_blueprint_catalog(
        args.blueprints,
        registry,
        catalog,
        standard,
        plans,
    )
    components = load_candidate_component_catalog(
        args.components,
        blueprints,
    )
    candidates = load_candidate_implementation_catalog(
        args.candidates,
        registry,
        catalog,
        standard,
        plans,
        blueprints,
    )
    report = assess_specialist_implementation_roadmap(
        registry,
        catalog,
        policy,
        standard,
        plans,
        blueprints,
        components,
        candidates,
    )
    _write_json(report.to_dict(), args.output)


def _assess_capability_roadmap(args: argparse.Namespace) -> None:
    roadmap = load_capability_roadmap(args.roadmap)
    report = assess_capability_roadmap(
        roadmap,
        args.completed_package_id,
    )
    _write_json(report, args.output)


def _assess_implementation_work_packages(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    catalog = load_capability_catalog(args.capabilities, registry)
    policy = load_routing_policy(args.policy, catalog)
    standard = load_qualification_standard(
        args.standard,
        registry,
        catalog,
    )
    plans = load_qualification_plan_catalog(
        args.plans,
        registry,
        catalog,
        standard,
    )
    blueprints = load_candidate_blueprint_catalog(
        args.blueprints,
        registry,
        catalog,
        standard,
        plans,
    )
    components = load_candidate_component_catalog(
        args.components,
        blueprints,
    )
    candidates = load_candidate_implementation_catalog(
        args.candidates,
        registry,
        catalog,
        standard,
        plans,
        blueprints,
    )
    roadmap = load_specialist_implementation_roadmap(args.roadmap)
    report = assess_implementation_work_packages(
        registry,
        catalog,
        policy,
        standard,
        plans,
        blueprints,
        components,
        candidates,
        roadmap,
    )
    _write_json(report.to_dict(), args.output)


def _select_implementation_wave_package(
    args: argparse.Namespace,
) -> None:
    work_packages = load_implementation_work_package_report(args.packages)
    report = select_implementation_wave_package(
        work_packages,
        args.wave_id,
    )
    _write_json(report.to_dict(), args.output)


def _assess_qualification_authority_decision(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    catalog = load_capability_catalog(args.capabilities, registry)
    standard = load_qualification_standard(
        args.standard,
        registry,
        catalog,
    )
    roadmap = load_specialist_implementation_roadmap(args.roadmap)
    work_packages = load_implementation_work_package_report(args.packages)
    dossier = assess_qualification_authority_decision(
        registry,
        catalog,
        standard,
        roadmap,
        work_packages,
    )
    _write_json(dossier.to_dict(), args.output)


def _record_qualification_authority_decision(
    args: argparse.Namespace,
) -> None:
    dossier_path = Path(args.dossier)
    try:
        raw = loads_json_without_duplicate_keys(
            dossier_path.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise SunderkeyError(
            f"Could not load qualification authority dossier: {dossier_path}"
        ) from exc
    dossier = QualificationAuthorityDecisionDossier.from_dict(raw)
    record = record_qualification_authority_decision(dossier)
    _write_json(record.to_dict(), args.output)


def _assess_candidate_enrollment_decision(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    catalog = load_capability_catalog(args.capabilities, registry)
    standard = load_qualification_standard(
        args.standard,
        registry,
        catalog,
    )
    authority_decision = load_qualification_authority_decision_record(
        args.authority_decision
    )
    dossier = assess_candidate_enrollment_decision(
        registry,
        catalog,
        standard,
        authority_decision,
    )
    _write_json(dossier.to_dict(), args.output)


def _candidate_enrollment_decision_template_create(
    args: argparse.Namespace,
) -> None:
    output = _require_new_output_path(args.output)
    dossier = load_candidate_enrollment_decision_dossier(args.dossier)
    template = build_candidate_enrollment_decision_submission_template(dossier)
    _write_json_exclusive(template, str(output))


def _candidate_enrollment_decision_record(
    args: argparse.Namespace,
) -> None:
    output = _require_new_output_path(args.output)
    dossier = load_candidate_enrollment_decision_dossier(args.dossier)
    submission = load_candidate_enrollment_decision_submission(args.submission)
    record = record_candidate_enrollment_decision(dossier, submission)
    _write_json_exclusive(record.to_dict(), str(output))
    document = record.to_dict()
    _write_json(
        {
            "record_id": record.record_id,
            "record_sha256": record.record_sha256,
            "decision_id": document["decision_id"],
            "decision_status": document["decision_status"],
            "decision_effect": document["decision_effect"],
            "recommendation_alignment": document["recommendation_alignment"],
            "implementation_status": document["implementation_status"],
            "qualification_effect": document["qualification_effect"],
            "network_call_performed": False,
            "status": "valid",
        },
        None,
    )


def _verify_candidate_enrollment_decision_record(
    args: argparse.Namespace,
) -> None:
    dossier = load_candidate_enrollment_decision_dossier(args.dossier)
    record = load_candidate_enrollment_decision_record(args.record)
    verified = verify_candidate_enrollment_decision_record(record, dossier)
    document = verified.to_dict()
    _write_json(
        {
            "record_id": verified.record_id,
            "record_sha256": verified.record_sha256,
            "decision_id": document["decision_id"],
            "decision_status": document["decision_status"],
            "decision_effect": document["decision_effect"],
            "recommendation_alignment": document["recommendation_alignment"],
            "implementation_status": document["implementation_status"],
            "qualification_effect": document["qualification_effect"],
            "network_call_performed": False,
            "status": "valid",
        },
        args.output,
    )


def _prepare_candidate_enrollment_deployment(
    args: argparse.Namespace,
) -> None:
    implementation = load_candidate_enrollment_implementation_report(
        args.implementation
    )
    packet = build_candidate_enrollment_deployment_preparation(implementation)
    _write_json(packet.to_dict(), args.output)


def _build_candidate_enrollment_activation_dossier(
    args: argparse.Namespace,
) -> None:
    schema_path = Path(args.verification_receipt_schema)
    try:
        schema = loads_json_without_duplicate_keys(
            schema_path.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise SunderkeyError(
            f"Could not load verification receipt schema: {schema_path}"
        ) from exc
    dossier = build_candidate_enrollment_activation_decision_dossier(
        load_candidate_enrollment_decision_record(args.d009_decision),
        load_candidate_enrollment_implementation_report(args.implementation),
        load_candidate_enrollment_deployment_preparation(args.preparation),
        schema,
    )
    _write_json(dossier.to_dict(), args.output)


def _candidate_enrollment_activation_decision_template_create(
    args: argparse.Namespace,
) -> None:
    output = _require_new_output_path(args.output)
    dossier = load_candidate_enrollment_activation_decision_dossier(args.dossier)
    template = build_candidate_enrollment_activation_decision_submission_template(
        dossier
    )
    _write_json_exclusive(template, str(output))


def _candidate_enrollment_activation_decision_record(
    args: argparse.Namespace,
) -> None:
    output = _require_new_output_path(args.output)
    dossier = load_candidate_enrollment_activation_decision_dossier(args.dossier)
    submission = load_candidate_enrollment_activation_decision_submission(
        args.submission
    )
    record = record_candidate_enrollment_activation_decision(dossier, submission)
    _write_json_exclusive(record.to_dict(), str(output))
    document = record.to_dict()
    _write_json(
        {
            "record_id": record.record_id,
            "record_sha256": record.record_sha256,
            "decision_id": document["decision_id"],
            "decision_status": document["decision_status"],
            "decision_effect": document["decision_effect"],
            "recommendation_alignment": document["recommendation_alignment"],
            "implementation_status": document["implementation_status"],
            "qualification_effect": document["qualification_effect"],
            "network_call_performed": False,
            "status": "valid",
        },
        None,
    )


def _verify_candidate_enrollment_activation_decision_record(
    args: argparse.Namespace,
) -> None:
    dossier = load_candidate_enrollment_activation_decision_dossier(args.dossier)
    record = load_candidate_enrollment_activation_decision_record(args.record)
    verified = verify_candidate_enrollment_activation_decision_record(record, dossier)
    document = verified.to_dict()
    _write_json(
        {
            "record_id": verified.record_id,
            "record_sha256": verified.record_sha256,
            "decision_id": document["decision_id"],
            "decision_status": document["decision_status"],
            "decision_effect": document["decision_effect"],
            "recommendation_alignment": document["recommendation_alignment"],
            "implementation_status": document["implementation_status"],
            "qualification_effect": document["qualification_effect"],
            "network_call_performed": False,
            "status": "valid",
        },
        args.output,
    )


def _build_candidate_enrollment_release_policy(args: argparse.Namespace) -> None:
    decision = load_candidate_enrollment_activation_decision_record(args.decision)
    policy = build_candidate_enrollment_release_policy(decision)
    _write_json(policy.to_dict(), args.output)


def _verify_candidate_enrollment_release_policy(args: argparse.Namespace) -> None:
    decision = load_candidate_enrollment_activation_decision_record(args.decision)
    policy = load_candidate_enrollment_release_policy(args.policy)
    expected = build_candidate_enrollment_release_policy(decision)
    if policy != expected:
        raise SunderkeyError("Candidate enrollment release policy does not match D011")
    _write_json(
        {
            "policy_id": policy.policy_id,
            "policy_sha256": policy.policy_sha256,
            "decision_id": "D011",
            "implementation_effect": policy.to_dict()["implementation_effect"],
            "qualification_effect": "none",
            "network_call_performed": False,
            "status": "valid",
        },
        args.output,
    )


def _candidate_enrollment_canary_inputs(args: argparse.Namespace) -> tuple[Any, ...]:
    schemas: list[Any] = []
    for path_value, label in (
        (args.normal_completion_schema, "normal completion schema"),
        (args.recovery_completion_schema, "recovery completion schema"),
    ):
        path = Path(path_value)
        try:
            schemas.append(
                loads_json_without_duplicate_keys(path.read_text(encoding="utf-8"))
            )
        except (OSError, UnicodeError, ValueError) as exc:
            raise SunderkeyError(f"Could not load {label}: {path}") from exc
    return (
        load_candidate_enrollment_activation_decision_record(args.decision),
        load_candidate_enrollment_release_policy(args.policy),
        *schemas,
    )


def _build_candidate_enrollment_canary_preparation(args: argparse.Namespace) -> None:
    packet = build_candidate_enrollment_canary_preparation(
        *_candidate_enrollment_canary_inputs(args)
    )
    _write_json(packet.to_dict(), args.output)


def _verify_candidate_enrollment_canary_preparation(args: argparse.Namespace) -> None:
    packet = load_candidate_enrollment_canary_preparation(args.packet)
    expected = build_candidate_enrollment_canary_preparation(
        *_candidate_enrollment_canary_inputs(args)
    )
    if packet != expected:
        raise SunderkeyError("Canary preparation does not match approved D011 inputs")
    document = packet.to_dict()
    _write_json(
        {
            "packet_id": packet.packet_id,
            "packet_sha256": packet.packet_sha256,
            "preparation_status": document["preparation_status"],
            "external_input_count": len(document["required_external_inputs"]),
            "authorized_next_action": document["authorized_next_action"],
            "network_call_performed": False,
            "qualification_effect": "none",
            "status": "valid",
        },
        args.output,
    )


def _candidate_enrollment_activation_implementation_inputs(
    args: argparse.Namespace,
) -> tuple[Any, ...]:
    return (
        load_candidate_enrollment_activation_decision_record(args.decision),
        load_candidate_enrollment_release_policy(args.policy),
        load_candidate_enrollment_canary_preparation(args.canary),
    )


def _build_candidate_enrollment_activation_implementation(
    args: argparse.Namespace,
) -> None:
    report = build_candidate_enrollment_activation_implementation_report(
        *_candidate_enrollment_activation_implementation_inputs(args)
    )
    _write_json(report.to_dict(), args.output)


def _verify_candidate_enrollment_activation_implementation(
    args: argparse.Namespace,
) -> None:
    report = load_candidate_enrollment_activation_implementation_report(args.report)
    expected = build_candidate_enrollment_activation_implementation_report(
        *_candidate_enrollment_activation_implementation_inputs(args)
    )
    if report != expected:
        raise SunderkeyError("Activation implementation report does not match D011")
    document = report.to_dict()
    _write_json(
        {
            "report_id": report.report_id,
            "report_sha256": report.report_sha256,
            "implementation_status": document["implementation_status"],
            "implemented_step_count": len(document["implemented_steps"]),
            "live_activation_status": document["live_activation_status"],
            "production_prerequisite_count": len(
                document["production_prerequisites"]
            ),
            "network_call_performed": False,
            "qualification_effect": "none",
            "status": "valid",
        },
        args.output,
    )


def _build_candidate_enrollment_production_custody_dossier(
    args: argparse.Namespace,
) -> None:
    dossier = build_candidate_enrollment_production_custody_dossier(
        load_candidate_enrollment_activation_implementation_report(
            args.implementation
        ),
        load_candidate_enrollment_canary_preparation(args.canary),
    )
    _write_json(dossier.to_dict(), args.output)


def _candidate_enrollment_production_custody_decision_template_create(
    args: argparse.Namespace,
) -> None:
    output = _require_new_output_path(args.output)
    dossier = load_candidate_enrollment_production_custody_dossier(args.dossier)
    template = build_candidate_enrollment_production_custody_decision_submission_template(
        dossier
    )
    _write_json_exclusive(template, str(output))


def _candidate_enrollment_production_custody_decision_record(
    args: argparse.Namespace,
) -> None:
    output = _require_new_output_path(args.output)
    record = record_candidate_enrollment_production_custody_decision(
        load_candidate_enrollment_production_custody_dossier(args.dossier),
        load_candidate_enrollment_production_custody_decision_submission(
            args.submission
        ),
    )
    _write_json_exclusive(record.to_dict(), str(output))
    document = record.to_dict()
    _write_json(
        {
            "record_id": record.record_id,
            "record_sha256": record.record_sha256,
            "decision_id": document["decision_id"],
            "decision_status": document["decision_status"],
            "decision_effect": document["decision_effect"],
            "recommendation_alignment": document["recommendation_alignment"],
            "implementation_status": document["implementation_status"],
            "qualification_effect": document["qualification_effect"],
            "network_call_performed": False,
            "status": "valid",
        },
        None,
    )


def _verify_candidate_enrollment_production_custody_decision_record(
    args: argparse.Namespace,
) -> None:
    dossier = load_candidate_enrollment_production_custody_dossier(args.dossier)
    record = load_candidate_enrollment_production_custody_decision_record(args.record)
    verified = verify_candidate_enrollment_production_custody_decision_record(
        record, dossier
    )
    document = verified.to_dict()
    _write_json(
        {
            "record_id": verified.record_id,
            "record_sha256": verified.record_sha256,
            "decision_id": document["decision_id"],
            "decision_status": document["decision_status"],
            "decision_effect": document["decision_effect"],
            "recommendation_alignment": document["recommendation_alignment"],
            "implementation_status": document["implementation_status"],
            "qualification_effect": document["qualification_effect"],
            "network_call_performed": False,
            "status": "valid",
        },
        args.output,
    )


def _create_candidate_enrollment_deployment_worksheet(
    args: argparse.Namespace,
) -> None:
    output = _require_new_output_path(args.output)
    packet = load_candidate_enrollment_deployment_preparation(args.preparation)
    worksheet = build_candidate_enrollment_deployment_worksheet(packet)
    _write_json_exclusive(worksheet.to_dict(), str(output))


def _preflight_candidate_enrollment_deployment_inputs(
    args: argparse.Namespace,
) -> None:
    packet = load_candidate_enrollment_deployment_preparation(args.preparation)
    worksheet = load_candidate_enrollment_deployment_worksheet(args.worksheet)
    report = assess_candidate_enrollment_deployment_inputs(packet, worksheet)
    _write_json(report.to_dict(), args.output)


def _candidate_enrollment_deployment_artifacts(
    args: argparse.Namespace,
) -> tuple[object, ...]:
    registry = load_registry(args.registry)
    capabilities = load_capability_catalog(args.capabilities, registry)
    standard = load_qualification_standard(args.standard, registry, capabilities)
    return (
        load_candidate_enrollment_deployment_preparation(args.preparation),
        load_candidate_enrollment_deployment_worksheet(args.worksheet),
        load_candidate_enrollment_deployment_preflight(args.preflight),
        load_candidate_enrollment_deployment_verification_context(args.context),
        standard,
        load_qualification_authority_decision_record(args.d008_decision),
        load_candidate_enrollment_decision_record(args.d009_decision),
        load_qualification_trust_policy(args.policy),
        load_candidate_enrollment_signer_authorization(args.authorization),
        load_qualification_reviewer_credential(args.control_credential),
        load_qualification_reviewer_credential(args.assurance_credential),
        load_candidate_enrollment_catalog(args.catalog),
    )


def _candidate_enrollment_verification_summary(receipt: Any) -> dict[str, Any]:
    document = receipt.to_dict()
    return {
        "receipt_id": receipt.receipt_id,
        "receipt_sha256": receipt.receipt_sha256,
        "verification_status": document["verification_status"],
        "next_checkpoint": document["next_checkpoint"],
        "readiness": document["readiness"],
        "network_call_performed": False,
        "qualification_effect": "none",
        "status": "valid",
    }


def _verify_candidate_enrollment_deployment_artifacts(
    args: argparse.Namespace,
) -> None:
    output = _require_new_output_path(args.output)
    receipt = verify_candidate_enrollment_deployment_artifacts(
        *_candidate_enrollment_deployment_artifacts(args)
    )
    _write_json_exclusive(receipt.to_dict(), str(output))
    _write_json(_candidate_enrollment_verification_summary(receipt), None)


def _verify_candidate_enrollment_deployment_receipt(
    args: argparse.Namespace,
) -> None:
    receipt = verify_candidate_enrollment_deployment_verification_receipt(
        load_candidate_enrollment_deployment_verification_receipt(args.receipt),
        *_candidate_enrollment_deployment_artifacts(args),
    )
    _write_json(_candidate_enrollment_verification_summary(receipt), args.output)


def _assess_collaboration_authority_decisions(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    catalog = load_capability_catalog(args.capabilities, registry)
    policy = load_routing_policy(args.policy, catalog)
    dossier = assess_collaboration_authority_decisions(
        registry,
        catalog,
        policy,
    )
    _write_json(dossier.to_dict(), args.output)


def _collaboration_authority_decision_template_create(
    args: argparse.Namespace,
) -> None:
    output = _require_new_output_path(args.output)
    dossier = load_collaboration_authority_decision_dossier(args.dossier)
    template = build_collaboration_authority_decision_submission_template(dossier)
    _write_json_exclusive(template, str(output))


def _collaboration_authority_decision_record(args: argparse.Namespace) -> None:
    output = _require_new_output_path(args.output)
    record = record_collaboration_authority_decision(
        load_collaboration_authority_decision_dossier(args.dossier),
        load_collaboration_authority_decision_submission(args.submission),
    )
    _write_json_exclusive(record.to_dict(), str(output))
    document = record.to_dict()
    _write_json(
        {
            "record_id": record.record_id,
            "record_sha256": record.record_sha256,
            "decision_ids": document["decision_ids"],
            "decision_status": document["decision_status"],
            "decision_effect": document["decision_effect"],
            "recommendation_alignment": document["recommendation_alignment"],
            "implementation_status": document["implementation_status"],
            "runtime_effect": document["runtime_effect"],
            "network_call_performed": False,
            "status": "valid",
        },
        None,
    )


def _verify_collaboration_authority_decision_record(
    args: argparse.Namespace,
) -> None:
    dossier = load_collaboration_authority_decision_dossier(args.dossier)
    record = load_collaboration_authority_decision_record(args.record)
    verified = verify_collaboration_authority_decision_record(record, dossier)
    document = verified.to_dict()
    _write_json(
        {
            "record_id": verified.record_id,
            "record_sha256": verified.record_sha256,
            "decision_ids": document["decision_ids"],
            "decision_status": document["decision_status"],
            "decision_effect": document["decision_effect"],
            "recommendation_alignment": document["recommendation_alignment"],
            "implementation_status": document["implementation_status"],
            "runtime_effect": document["runtime_effect"],
            "network_call_performed": False,
            "status": "valid",
        },
        args.output,
    )


def _build_collaboration_reconfiguration_policy(args: argparse.Namespace) -> None:
    policy = build_collaboration_reconfiguration_authority_policy(
        load_collaboration_authority_decision_record(args.decision)
    )
    _write_json(policy.to_dict(), args.output)


def _verify_collaboration_reconfiguration_policy(args: argparse.Namespace) -> None:
    policy = load_collaboration_reconfiguration_authority_policy(args.policy)
    expected = build_collaboration_reconfiguration_authority_policy(
        load_collaboration_authority_decision_record(args.decision)
    )
    if policy != expected:
        raise SunderkeyError("Reconfiguration policy does not match the approved decisions")
    document = policy.to_dict()
    _write_json(
        {
            "policy_id": policy.policy_id,
            "policy_sha256": policy.policy_sha256,
            "approved_model": document["approved_model"],
            "policy_status": document["current_boundary"]["policy_status"],
            "transition_rule_count": len(document["transition_rules"]),
            "selected_parameter_count": sum(
                item["selected_value"] is not None
                for item in document["parameter_contracts"]
            ),
            "runtime_effect": document["runtime_effect"],
            "network_call_performed": False,
            "status": "valid",
        },
        args.output,
    )


def _assemble(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    mission = load_mission_request(args.mission)
    cell = assemble_joint_mission_cell(registry, mission)
    _write_json(cell.to_dict(), args.output)


def _plan_collaboration(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    mission = load_mission_request(args.mission)
    plan = build_collaboration_plan(registry, mission)
    _write_json(plan.to_dict(), args.output)


def _activate_collaboration_authenticated(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    plan = load_collaboration_plan(args.plan)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedCollaborationActivationService(
        MissionStore(args.store),
        registry,
    ).activate(
        assertion,
        plan,
    )
    _write_json(receipt.to_dict(), args.output)


def _show_collaboration_status(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    receipt = AuthenticatedCollaborationActivationService(
        MissionStore(args.store),
        registry,
    ).get(args.mission_id)
    _write_json(receipt.to_dict(), args.output)


def _collaboration_plan_replacement_operations_service(
    args: argparse.Namespace,
) -> CollaborationPlanReplacementOperationsService:
    registry = load_registry(args.registry)
    authority_policy = load_collaboration_reconfiguration_authority_policy(
        args.authority_policy
    )
    return CollaborationPlanReplacementOperationsService(
        MissionStore(args.store),
        registry,
        authority_policy,
        registry_source=Path(args.registry),
    )


def _assess_collaboration_plan_replacement_readiness(
    args: argparse.Namespace,
) -> None:
    readiness = _collaboration_plan_replacement_operations_service(args).assess(
        replacement_plan=load_collaboration_plan(args.replacement_plan),
        mapping_intents=load_collaboration_plan_replacement_mapping_intents(
            args.mapping_intents
        ),
        independent_assurance_profile_id=args.independent_assurance_profile_id,
        independent_control_profile_id=getattr(args, "independent_control_profile_id", None),
        second_control_profile_id=args.second_control_profile_id,
    )
    _write_json(readiness.to_dict(), args.output)


def _prepare_collaboration_plan_replacement(args: argparse.Namespace) -> None:
    preparation = _collaboration_plan_replacement_operations_service(args).prepare(
        replacement_plan=load_collaboration_plan(args.replacement_plan),
        mapping_intents=load_collaboration_plan_replacement_mapping_intents(
            args.mapping_intents
        ),
        issued_at=args.issued_at,
        expires_at=args.expires_at,
        independent_assurance_profile_id=args.independent_assurance_profile_id,
        independent_control_profile_id=getattr(args, "independent_control_profile_id", None),
        second_control_profile_id=args.second_control_profile_id,
    )
    _write_json_exclusive(preparation.to_dict(), args.output)


def _execute_collaboration_plan_replacement(args: argparse.Namespace) -> None:
    receipt = _collaboration_plan_replacement_operations_service(args).execute(
        preparation=load_prepared_collaboration_plan_replacement(args.preparation),
        credentials=load_collaboration_plan_replacement_credentials(args.credentials),
    )
    _write_json(receipt.to_dict(), args.output)


def _plan_replacement_reviewer_admission_service(
    args: argparse.Namespace,
) -> AuthenticatedPlanReplacementReviewerAdmissionService:
    registry = load_registry(args.registry)
    return AuthenticatedPlanReplacementReviewerAdmissionService(MissionStore(args.store), registry)


def _prepare_plan_replacement_reviewer_admission(args: argparse.Namespace) -> None:
    output = _require_new_output_path(args.output)
    grant = load_scope_grant(args.scope_grant)
    request = _plan_replacement_reviewer_admission_service(args).prepare(
        args.mission_id,
        admission_id=args.admission_id,
        reviewer_scope_grant=grant,
        reviewer_issuer=args.reviewer_issuer,
        reviewer_subject=args.reviewer_subject,
        role=args.role,
        issued_at=args.issued_at,
        not_before=args.not_before,
        expires_at=args.expires_at,
    )
    _write_json_exclusive(request.to_dict(), str(output))


def _plan_replacement_reviewer_admission_approval_intents(
    args: argparse.Namespace,
) -> None:
    output = _require_new_output_path(args.output)
    request = load_plan_replacement_reviewer_admission_request(args.request)
    packet = build_plan_replacement_reviewer_admission_approval_intents(
        request,
        mission_owner_profile_id=args.mission_owner_profile_id,
        independent_control_profile_id=args.independent_control_profile_id,
    )
    _write_json_exclusive(packet.to_dict(), str(output))


def _admit_plan_replacement_reviewer(args: argparse.Namespace) -> None:
    request = load_plan_replacement_reviewer_admission_request(args.request)
    owner = load_principal_assertion(args.mission_owner_assertion)
    control = load_principal_assertion(args.independent_control_assertion)
    receipt = _plan_replacement_reviewer_admission_service(args).admit(
        request,
        mission_owner_assertion=owner,
        independent_control_assertion=control,
    )
    _write_json(receipt.to_dict(), None)


def _show_plan_replacement_reviewer_admission(args: argparse.Namespace) -> None:
    receipt = _plan_replacement_reviewer_admission_service(args).get(
        args.mission_id, args.admission_id
    )
    _write_json(
        {
            "verification_scope": "historical_custody_only",
            "current_authority_verified": False,
            "receipt": receipt.to_dict(),
        },
        None,
    )


def _show_provider_evidence_repository_authentication(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    receipt = read_provider_evidence_repository_ingest_authentication(
        MissionStore(args.store), registry, args.authentication_id
    )
    _write_json(
        {
            "verification_scope": "historical_custody_only",
            "current_authority_verified": False,
            "receipt": receipt.to_dict(),
        },
        None,
    )


def _commit_collaboration_mission_policy(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    policy = load_collaboration_mission_reconfiguration_policy(
        args.mission_policy
    )
    authority_policy = load_collaboration_reconfiguration_authority_policy(
        args.authority_policy
    )
    mission_owner_assertion = load_principal_assertion(
        args.mission_owner_assertion
    )
    independent_control_assertion = load_principal_assertion(
        args.independent_control_assertion
    )
    receipt = AuthenticatedCollaborationMissionPolicyService(
        MissionStore(args.store),
        registry,
    ).commit(
        policy,
        authority_policy=authority_policy,
        mission_owner_assertion=mission_owner_assertion,
        independent_control_assertion=independent_control_assertion,
    )
    _write_json(receipt.to_dict(), args.output)


def _show_collaboration_mission_policy(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    receipt = AuthenticatedCollaborationMissionPolicyService(
        MissionStore(args.store),
        registry,
    ).get(
        args.mission_id,
        policy_version=args.policy_version,
    )
    _write_json(receipt.to_dict(), args.output)


def _preflight_collaboration_ownership_transition(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    entry = load_collaboration_ownership_chain_entry(
        args.ownership_entry
    )
    receipt = CollaborationOwnershipTransitionPreflightService(
        MissionStore(args.store),
        registry,
    ).preflight(entry)
    _write_json(receipt.to_dict(), args.output)


def _commit_collaboration_ownership_transition(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    preflight = load_collaboration_ownership_transition_preflight(
        args.preflight
    )
    current_owner_assertion = load_principal_assertion(
        args.current_owner_assertion
    )
    proposed_owner_assertion = load_principal_assertion(
        args.proposed_owner_assertion
    )
    independent_control_assertion = load_principal_assertion(
        args.independent_control_assertion
    )
    receipt = AuthenticatedCollaborationOwnershipService(
        MissionStore(args.store),
        registry,
    ).commit(
        preflight,
        current_owner_assertion=current_owner_assertion,
        proposed_owner_assertion=proposed_owner_assertion,
        independent_control_assertion=independent_control_assertion,
    )
    _write_json(receipt.to_dict(), args.output)


def _show_collaboration_ownership_transition(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    receipt = AuthenticatedCollaborationOwnershipService(
        MissionStore(args.store),
        registry,
    ).get(
        args.mission_id,
        args.work_item_id,
        entry_id=args.entry_id,
    )
    _write_json(receipt.to_dict(), args.output)


def _preflight_collaboration_ownership_privileged_reassignment(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    entry = load_collaboration_ownership_chain_entry(
        args.ownership_entry
    )
    receipt = CollaborationOwnershipPrivilegedReassignmentPreflightService(
        MissionStore(args.store),
        registry,
    ).preflight(entry)
    _write_json(receipt.to_dict(), args.output)


def _commit_collaboration_ownership_privileged_reassignment(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    preflight = load_collaboration_ownership_privileged_reassignment_preflight(
        args.preflight
    )
    current_owner_assertion = load_principal_assertion(
        args.current_owner_assertion
    )
    proposed_owner_assertion = load_principal_assertion(
        args.proposed_owner_assertion
    )
    independent_control_assertion = load_principal_assertion(
        args.independent_control_assertion
    )
    second_authority_assertion = (
        None
        if args.second_authority_assertion is None
        else load_principal_assertion(args.second_authority_assertion)
    )
    receipt = (
        AuthenticatedCollaborationOwnershipPrivilegedReassignmentService(
            MissionStore(args.store),
            registry,
        ).commit(
            preflight,
            current_owner_assertion=current_owner_assertion,
            proposed_owner_assertion=proposed_owner_assertion,
            independent_control_assertion=independent_control_assertion,
            second_authority_assertion=second_authority_assertion,
        )
    )
    _write_json(receipt.to_dict(), args.output)


def _show_collaboration_ownership_privileged_reassignment(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    receipt = (
        AuthenticatedCollaborationOwnershipPrivilegedReassignmentService(
            MissionStore(args.store),
            registry,
        ).get(
            args.mission_id,
            args.work_item_id,
            entry_id=args.entry_id,
        )
    )
    _write_json(receipt.to_dict(), args.output)


def _preflight_collaboration_ownership_revocation(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    revocation = load_collaboration_ownership_revocation(args.revocation)
    receipt = CollaborationOwnershipRevocationPreflightService(
        MissionStore(args.store),
        registry,
    ).preflight(revocation)
    _write_json(receipt.to_dict(), args.output)


def _commit_collaboration_ownership_revocation(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    preflight = load_collaboration_ownership_revocation_preflight(
        args.preflight
    )
    planned_owner_assertion = load_principal_assertion(
        args.planned_owner_assertion
    )
    independent_control_assertion = load_principal_assertion(
        args.independent_control_assertion
    )
    receipt = AuthenticatedCollaborationOwnershipRevocationService(
        MissionStore(args.store),
        registry,
    ).commit(
        preflight,
        planned_owner_assertion=planned_owner_assertion,
        independent_control_assertion=independent_control_assertion,
    )
    _write_json(receipt.to_dict(), args.output)


def _show_collaboration_ownership_revocation(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    receipt = AuthenticatedCollaborationOwnershipRevocationService(
        MissionStore(args.store),
        registry,
    ).get(
        args.mission_id,
        args.work_item_id,
        entry_id=args.entry_id,
    )
    _write_json(receipt.to_dict(), args.output)


def _claim_work_item_authenticated(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedWorkItemLeaseService(
        MissionStore(args.store),
        registry,
    ).claim(
        assertion,
        args.mission_id,
        args.work_item_id,
        expected_generation=args.expected_generation,
    )
    _write_json(receipt.to_dict(), args.output)


def _renew_work_item_authenticated(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedWorkItemLeaseService(
        MissionStore(args.store),
        registry,
    ).renew(
        assertion,
        args.mission_id,
        args.work_item_id,
        claim_generation=args.claim_generation,
        previous_transition_id=args.previous_transition_id,
        expected_lease_expires_at=(
            args.expected_lease_expires_at
        ),
    )
    _write_json(receipt.to_dict(), args.output)


def _release_work_item_authenticated(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedWorkItemLeaseService(
        MissionStore(args.store),
        registry,
    ).release(
        assertion,
        args.mission_id,
        args.work_item_id,
        claim_generation=args.claim_generation,
        previous_transition_id=args.previous_transition_id,
        expected_lease_expires_at=(
            args.expected_lease_expires_at
        ),
        reason_code=args.reason_code,
        reason=args.reason,
    )
    _write_json(receipt.to_dict(), args.output)


def _complete_work_item_authenticated(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedWorkItemLeaseService(
        MissionStore(args.store),
        registry,
    ).complete(
        assertion,
        args.mission_id,
        args.work_item_id,
        claim_generation=args.claim_generation,
        previous_transition_id=args.previous_transition_id,
        expected_lease_expires_at=(
            args.expected_lease_expires_at
        ),
        result_id=args.result_id,
        result_sha256=args.result_sha256,
        evidence_manifest_sha256=(
            args.evidence_manifest_sha256
        ),
    )
    _write_json(receipt.to_dict(), args.output)


def _show_work_item_status(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    receipt = AuthenticatedWorkItemLeaseService(
        MissionStore(args.store),
        registry,
    ).status(
        args.mission_id,
        work_item_id=args.work_item_id,
    )
    _write_json(receipt.to_dict(), args.output)


def _create_mission_audit_snapshot(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    receipt = MissionAuditSnapshotService(
        MissionStore(args.store),
        registry,
    ).snapshot(args.mission_id)
    _write_json(receipt.to_dict(), args.output)


def _cancel_work_authenticated(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedWorkCancellationService(
        MissionStore(args.store),
        registry,
    ).cancel(
        assertion,
        args.mission_id,
        args.work_item_id,
        expected_generation=args.expected_generation,
        previous_transition_id=args.previous_transition_id,
        expected_lease_expires_at=args.expected_lease_expires_at,
        reason_code=args.reason_code,
        reason=args.reason,
        risk=args.risk,
        decision_owner=args.decision_owner,
    )
    _write_json(receipt.to_dict(), args.output)


def _show_work_cancellation(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    receipt = AuthenticatedWorkCancellationService(
        MissionStore(args.store),
        registry,
    ).get(args.cancellation_id)
    _write_json(receipt.to_dict(), args.output)


def _handoff_work_authenticated(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    owner_assertion = load_principal_assertion(
        args.owner_assertion
    )
    candidate_assertion = load_principal_assertion(
        args.candidate_assertion
    )
    receipt = AuthenticatedWorkHandoffService(
        MissionStore(args.store),
        registry,
    ).handoff(
        owner_assertion,
        candidate_assertion,
        args.mission_id,
        args.work_item_id,
        expected_generation=args.expected_generation,
        previous_transition_id=args.previous_transition_id,
        expected_lease_expires_at=args.expected_lease_expires_at,
        reason_code=args.reason_code,
        reason=args.reason,
    )
    _write_json(receipt.to_dict(), args.output)


def _show_work_handoff(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    receipt = AuthenticatedWorkHandoffService(
        MissionStore(args.store),
        registry,
    ).get(args.handoff_id)
    _write_json(receipt.to_dict(), args.output)


def _request_work_recovery_authenticated(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedWorkRecoveryService(
        MissionStore(args.store),
        registry,
    ).request(
        assertion,
        args.mission_id,
        args.work_item_id,
        expected_generation=args.expected_generation,
        previous_transition_id=args.previous_transition_id,
        expected_lease_expires_at=args.expected_lease_expires_at,
        reason_code=args.reason_code,
        reason=args.reason,
        remediation=args.remediation,
    )
    _write_json(receipt.to_dict(), args.output)


def _approve_work_recovery_authenticated(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedWorkRecoveryService(
        MissionStore(args.store),
        registry,
    ).approve(
        assertion,
        args.recovery_request_id,
        decision_owner=args.decision_owner,
        authority=args.authority,
        constraints=args.constraint,
    )
    _write_json(receipt.to_dict(), args.output)


def _deny_work_recovery_authenticated(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedWorkRecoveryService(
        MissionStore(args.store),
        registry,
    ).deny(
        assertion,
        args.recovery_request_id,
        decision_owner=args.decision_owner,
        reason_code=args.reason_code,
        reason=args.reason,
        risk=args.risk,
    )
    _write_json(receipt.to_dict(), args.output)


def _show_work_recovery_status(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    status = AuthenticatedWorkRecoveryService(
        MissionStore(args.store),
        registry,
    ).get(args.recovery_request_id)
    _write_json(status, args.output)


def _validate_events(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    mission = load_mission_request(args.mission)
    cell = assemble_joint_mission_cell(registry, mission)
    assigned_profile_ids = set(cell.all_profile_ids)
    assigned_profiles = (
        registry.profiles_by_id[profile_id]
        for profile_id in assigned_profile_ids
    )
    control_profile_ids: set[str] = set()
    assurance_profile_ids: set[str] = set()
    for profile in assigned_profiles:
        if "independent-control" in profile.tags:
            control_profile_ids.add(profile.id)
        if "independent-assurance" in profile.tags:
            assurance_profile_ids.add(profile.id)
    ledger = EventLedger(
        mission,
        allowed_profile_ids=assigned_profile_ids,
        control_profile_ids=control_profile_ids,
        assurance_profile_ids=assurance_profile_ids,
    )
    count = 0
    for event in _read_events(args.events):
        ledger.append(event)
        count += 1
    _write_json(
        {
            "mission_id": mission.mission_id,
            "event_count": count,
            "assigned_profile_count": cell.size,
            "status": "valid",
        },
        args.output,
    )


def _route(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    catalog = load_capability_catalog(args.capabilities, registry)
    policy = load_routing_policy(args.policy, catalog)
    request = load_routing_request(args.request)
    decision = route_mission(registry, catalog, policy, request)
    if args.mission_output is not None:
        if (
            args.output is not None
            and Path(args.output).resolve() == Path(args.mission_output).resolve()
        ):
            raise SunderkeyError(
                "Routing decision and mission output paths must differ"
            )
        _write_json(decision.mission_request.to_dict(), args.mission_output)
    _write_json(decision.to_dict(), args.output)


def _init_store(args: argparse.Namespace) -> None:
    store = MissionStore(args.store)
    store.initialize()
    trust_status = TrustProvisioningService(store).status()
    _write_json(
        {
            "status": "initialized",
            "store": str(store.path),
            "store_id": trust_status.store_id,
        },
        args.output,
    )


def _trust_status(args: argparse.Namespace) -> None:
    status = TrustProvisioningService(
        MissionStore(args.store)
    ).status()
    _write_json(status.to_dict(), args.output)


def _trust_pin_root(args: argparse.Namespace) -> None:
    status = TrustProvisioningService(
        MissionStore(args.store)
    ).pin_root(
        args.root_key_id,
        args.audience,
        args.root_public_key,
        args.expected_key_hash,
    )
    _write_json(status.to_dict(), args.output)


def _trust_apply_policy(args: argparse.Namespace) -> None:
    policy = load_principal_trust_policy(args.policy)
    status = TrustProvisioningService(
        MissionStore(args.store)
    ).apply_policy(policy)
    _write_json(status.to_dict(), args.output)


def _scope_accept(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    grant = load_scope_grant(args.scope_grant)
    acceptance = ScopeGrantAcceptanceService(
        MissionStore(args.store),
        registry,
    ).accept(grant)
    _write_json(acceptance.to_dict(), args.output)


def _scope_revoke(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    revocation = load_scope_grant_revocation(
        args.scope_grant_revocation
    )
    acceptance = ScopeGrantRevocationAcceptanceService(
        MissionStore(args.store),
        registry,
    ).accept(revocation)
    _write_json(acceptance.to_dict(), args.output)


def _migrate_store(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    store = MissionStore(args.store)
    report = store.migrate(registry, args.backup_destination)
    _write_json(report.to_dict(), args.output)


def _create_mission(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    mission = load_mission_request(args.mission)
    store = MissionStore(args.store)
    stored = store.create_mission(registry, mission)
    _write_json(stored.to_dict(), args.output)


def _create_mission_authenticated(
    args: argparse.Namespace,
) -> None:
    registry = load_registry(args.registry)
    mission = load_mission_request(args.mission)
    scope_grant = load_scope_grant(args.scope_grant)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedMissionCreationService(
        MissionStore(args.store),
        registry,
    ).create(
        assertion,
        scope_grant,
        mission,
    )
    _write_json(receipt.to_dict(), args.output)


def _show_mission(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    store = MissionStore(args.store)
    stored = store.get_mission(registry, args.mission_id)
    _write_json(stored.to_dict(), args.output)


def _list_missions(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    store = MissionStore(args.store)
    missions = store.list_missions(
        registry,
        limit=args.limit,
        after=args.after,
    )
    _write_json(
        {
            "missions": [mission.to_dict() for mission in missions],
            "count": len(missions),
        },
        args.output,
    )


def _append_events(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    events = _read_events(args.events)
    mission_ids = {event.mission_id for event in events}
    if len(mission_ids) != 1:
        raise SunderkeyError(
            "Every event in an append batch must use one mission ID"
        )
    mission_id = next(iter(mission_ids))
    if args.mission_id is not None and args.mission_id != mission_id:
        raise SunderkeyError(
            "The command mission ID does not match the event batch"
        )
    store = MissionStore(args.store)
    receipts = store.append_events(
        registry,
        mission_id,
        events,
        expected_revision=args.expected_revision,
    )
    _write_json(
        {
            "mission_id": mission_id,
            "receipts": [receipt.to_dict() for receipt in receipts],
        },
        args.output,
    )


def _append_events_authenticated(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    events = _read_events(args.events)
    mission_ids = {event.mission_id for event in events}
    if len(mission_ids) != 1:
        raise SunderkeyError(
            "Every event in an append batch must use one mission ID"
        )
    event_mission_id = next(iter(mission_ids))
    if args.mission_id != event_mission_id:
        raise SunderkeyError(
            "The command mission ID does not match the event batch"
        )
    receipt = AuthenticatedEventAppendService(
        MissionStore(args.store),
        registry,
    ).append(
        assertion,
        args.mission_id,
        events,
        expected_revision=args.expected_revision,
    )
    _write_json(receipt.to_dict(), args.output)


def _export_events(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    store = MissionStore(args.store)
    events = store.list_events(
        registry,
        args.mission_id,
        after_sequence=args.after_sequence,
        limit=args.limit,
    )
    _write_json(
        {
            "mission_id": args.mission_id,
            "events": [event.to_dict() for event in events],
            "count": len(events),
        },
        args.output,
    )


def _verify_store(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    store = MissionStore(args.store)
    if args.mission_id is None:
        report = store.verify_store(registry)
    else:
        report = store.verify_mission(registry, args.mission_id)
    _write_json(report.to_dict(), args.output)


def _backup_store(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    store = MissionStore(args.store)
    destination = store.backup(registry, args.destination)
    _write_json(
        {
            "status": "created",
            "destination": str(destination),
        },
        args.output,
    )


def _approval_submit(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    service = ApprovalService(MissionStore(args.store), registry)
    record = service.submit(
        mission_id=args.mission_id,
        proposal_id=args.proposal_id,
        executor_profile_id=args.executor_profile_id,
        review_expires_at=args.review_expires_at,
        idempotency_key=args.idempotency_key,
        principal_profile_id=args.principal_profile_id,
    )
    _write_json(record.to_dict(), args.output)


def _approval_submit_authenticated(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedApprovalSubmissionService(
        MissionStore(args.store),
        registry,
    ).submit(
        assertion,
        mission_id=args.mission_id,
        proposal_id=args.proposal_id,
        executor_profile_id=args.executor_profile_id,
        review_expires_at=args.review_expires_at,
        idempotency_key=args.idempotency_key,
    )
    _write_json(receipt.to_dict(), args.output)


def _approval_list(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    service = ApprovalService(MissionStore(args.store), registry)
    state = ApprovalState(args.state) if args.state is not None else None
    records = service.list(args.mission_id, state=state)
    _write_json(
        {
            "mission_id": args.mission_id,
            "approvals": [record.to_dict() for record in records],
            "count": len(records),
        },
        args.output,
    )


def _approval_approve(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    service = ApprovalService(MissionStore(args.store), registry)
    record = service.approve(
        args.approval_id,
        authority=args.authority,
        constraints=args.constraint,
        authorization_expires_at=args.authorization_expires_at,
        idempotency_key=args.idempotency_key,
        expected_version=args.expected_version,
        principal_profile_id=args.principal_profile_id,
    )
    _write_json(record.to_dict(), args.output)


def _approval_approve_authenticated(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedApprovalDecisionService(
        MissionStore(args.store),
        registry,
    ).approve(
        assertion,
        args.approval_id,
        authority=args.authority,
        constraints=args.constraint,
        authorization_expires_at=args.authorization_expires_at,
        idempotency_key=args.idempotency_key,
        expected_version=args.expected_version,
    )
    _write_json(receipt.to_dict(), args.output)


def _approval_deny(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    service = ApprovalService(MissionStore(args.store), registry)
    record = service.deny(
        args.approval_id,
        reason_code=args.reason_code,
        reason=args.reason,
        risk=args.risk,
        decision_owner=args.decision_owner,
        idempotency_key=args.idempotency_key,
        expected_version=args.expected_version,
        principal_profile_id=args.principal_profile_id,
    )
    _write_json(record.to_dict(), args.output)


def _approval_deny_authenticated(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedApprovalDecisionService(
        MissionStore(args.store),
        registry,
    ).deny(
        assertion,
        args.approval_id,
        reason_code=args.reason_code,
        reason=args.reason,
        risk=args.risk,
        decision_owner=args.decision_owner,
        idempotency_key=args.idempotency_key,
        expected_version=args.expected_version,
    )
    _write_json(receipt.to_dict(), args.output)


def _approval_revoke(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    service = ApprovalService(MissionStore(args.store), registry)
    revocation = service.revoke(
        args.approval_id,
        reason_code=args.reason_code,
        reason=args.reason,
        risk=args.risk,
        decision_owner=args.decision_owner,
        idempotency_key=args.idempotency_key,
        expected_version=args.expected_version,
        principal_profile_id=args.principal_profile_id,
    )
    approval = service.get(args.approval_id)
    _write_json(
        {
            "approval": approval.to_dict(),
            "revocation": revocation.to_dict(),
        },
        args.output,
    )


def _approval_revoke_authenticated(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedApprovalRevocationService(
        MissionStore(args.store),
        registry,
    ).revoke(
        assertion,
        args.approval_id,
        reason_code=args.reason_code,
        reason=args.reason,
        risk=args.risk,
        decision_owner=args.decision_owner,
        idempotency_key=args.idempotency_key,
        expected_version=args.expected_version,
    )
    _write_json(receipt.to_dict(), args.output)


def _mission_status(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    service = MissionControlService(
        MissionStore(args.store),
        registry,
    )
    _write_json(service.get(args.mission_id).to_dict(), args.output)


def _mission_stop(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    service = MissionControlService(
        MissionStore(args.store),
        registry,
    )
    record = service.stop(
        args.mission_id,
        reason_code=args.reason_code,
        reason=args.reason,
        risk=args.risk,
        decision_owner=args.decision_owner,
        idempotency_key=args.idempotency_key,
        expected_version=args.expected_version,
        principal_profile_id=args.principal_profile_id,
    )
    _write_json(record.to_dict(), args.output)


def _mission_stop_authenticated(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedMissionControlService(
        MissionStore(args.store),
        registry,
    ).stop(
        assertion,
        args.mission_id,
        reason_code=args.reason_code,
        reason=args.reason,
        risk=args.risk,
        decision_owner=args.decision_owner,
        idempotency_key=args.idempotency_key,
        expected_version=args.expected_version,
    )
    _write_json(receipt.to_dict(), args.output)


def _simulate(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    service = SimulationService(MissionStore(args.store), registry)
    receipt = service.simulate(
        args.approval_id,
        idempotency_key=args.idempotency_key,
        principal_profile_id=args.principal_profile_id,
    )
    _write_json(receipt.to_dict(), args.output)


def _simulate_authenticated(args: argparse.Namespace) -> None:
    registry = load_registry(args.registry)
    assertion = load_principal_assertion(
        args.principal_assertion
    )
    receipt = AuthenticatedSimulationService(
        MissionStore(args.store),
        registry,
    ).simulate(
        assertion,
        args.approval_id,
        idempotency_key=args.idempotency_key,
    )
    _write_json(receipt.to_dict(), args.output)


def _check_content(args: argparse.Namespace) -> None:
    require_clean_repository_text(args.root)
    _write_json(
        {
            "root": str(Path(args.root).resolve()),
            "status": "valid",
        },
        args.output,
    )


def _read_offline_review_json(path: Path, maximum_bytes: int) -> Any:
    try:
        with path.open("rb") as stream:
            data = stream.read(maximum_bytes + 1)
        if len(data) > maximum_bytes:
            raise SunderkeyError("Offline review file exceeds its size limit")
        return loads_json_without_duplicate_keys(data.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        if isinstance(exc, SunderkeyError):
            raise
        raise SunderkeyError("Could not validate offline review file") from exc


def _run_offline_review(args: argparse.Namespace) -> None:
    request = _read_offline_review_json(Path(args.input), MAX_INPUT_BYTES)
    try:
        bundle = build_offline_review_bundle(request)
    except OfflineReviewWorkflowError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(bundle, None)


def _run_remediation_case_review(args: argparse.Namespace) -> None:
    try:
        request = load_remediation_case_request(args.input)
        review = build_remediation_case_review_from_request(request)
        rendered = serialize_remediation_case_review(review)
    except RemediationValidationError as exc:
        raise SunderkeyError(str(exc)) from exc
    binary_output = getattr(sys.stdout, "buffer", None)
    if binary_output is None:
        sys.stdout.write(rendered)
    else:
        binary_output.write(rendered.encode("ascii"))


def _verify_remediation_case_review(args: argparse.Namespace) -> None:
    try:
        request = load_remediation_case_request(args.input)
        review = load_remediation_case_review(args.review)
        verify_remediation_case_review_from_request(request, review)
    except RemediationValidationError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json({
        "schema_version": 1,
        "status": "valid",
        "verification_kind": "offline_source_replay",
        "case_review_sha256": review["case_review_sha256"],
        "plan_id": review["plan_id"],
        "case_status": "review_required",
        "live_source_freshness": "not_established",
        "effects": dict(REMEDIATION_CASE_NO_EFFECTS),
    }, None)


def _run_mcp_catalog_preflight(args: argparse.Namespace) -> None:
    manifest = _read_offline_review_json(Path(args.manifest), MAX_MCP_CATALOG_BYTES)
    try:
        result = build_mcp_catalog_preflight(manifest)
    except MCPCatalogPreflightError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(result, None)


def _verify_mcp_catalog_preflight(args: argparse.Namespace) -> None:
    manifest = _read_offline_review_json(Path(args.manifest), MAX_MCP_CATALOG_BYTES)
    preflight = _read_offline_review_json(
        Path(args.preflight), MAX_MCP_PREFLIGHT_BYTES,
    )
    try:
        result = verify_mcp_catalog_preflight(manifest, preflight)
    except MCPCatalogPreflightError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(result, None)


def _mcp_schema_sources(args: argparse.Namespace) -> tuple[Any, ...]:
    return (
        _read_offline_review_json(Path(args.manifest), MAX_MCP_CATALOG_BYTES),
        _read_offline_review_json(Path(args.preflight), MAX_MCP_PREFLIGHT_BYTES),
        _read_offline_review_json(Path(args.schemas), MAX_MCP_SCHEMA_BUNDLE_BYTES),
    )


def _run_mcp_schema_byte_preflight(args: argparse.Namespace) -> None:
    try:
        result = build_mcp_schema_byte_preflight(*_mcp_schema_sources(args))
    except MCPSchemaBytePreflightError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(result, None)


def _verify_mcp_schema_byte_preflight(args: argparse.Namespace) -> None:
    sources = _mcp_schema_sources(args)
    result = _read_offline_review_json(
        Path(args.result), MAX_MCP_SCHEMA_RESULT_BYTES,
    )
    try:
        verification = verify_mcp_schema_byte_preflight(*sources, result)
    except MCPSchemaBytePreflightError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(verification, None)


def _mcp_semantic_sources(args: argparse.Namespace) -> tuple[Any, ...]:
    return (
        *_mcp_schema_sources(args),
        _read_offline_review_json(
            Path(args.byte_result), MAX_MCP_SCHEMA_RESULT_BYTES,
        ),
    )


def _run_mcp_schema_semantic_preflight(args: argparse.Namespace) -> None:
    try:
        result = build_mcp_schema_semantic_preflight(*_mcp_semantic_sources(args))
    except MCPSchemaSemanticPreflightError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(result, None)


def _verify_mcp_schema_semantic_preflight(args: argparse.Namespace) -> None:
    sources = _mcp_semantic_sources(args)
    result = _read_offline_review_json(
        Path(args.result), MAX_MCP_SCHEMA_RESULT_BYTES,
    )
    try:
        verification = verify_mcp_schema_semantic_preflight(*sources, result)
    except MCPSchemaSemanticPreflightError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(verification, None)


def _mcp_header_sources(args: argparse.Namespace) -> tuple[Any, ...]:
    return (
        *_mcp_semantic_sources(args),
        _read_offline_review_json(
            Path(args.semantic_result), MAX_MCP_SCHEMA_RESULT_BYTES,
        ),
    )


def _run_mcp_header_annotation_preflight(args: argparse.Namespace) -> None:
    try:
        result = build_mcp_header_annotation_preflight(*_mcp_header_sources(args))
    except MCPHeaderAnnotationPreflightError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(result, None)


def _verify_mcp_header_annotation_preflight(args: argparse.Namespace) -> None:
    sources = _mcp_header_sources(args)
    result = _read_offline_review_json(
        Path(args.result), MAX_MCP_SCHEMA_RESULT_BYTES,
    )
    try:
        verification = verify_mcp_header_annotation_preflight(*sources, result)
    except MCPHeaderAnnotationPreflightError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(verification, None)


def _mcp_api_binding_sources(args: argparse.Namespace) -> tuple[Any, ...]:
    return (
        _read_offline_review_json(Path(args.manifest), MAX_MCP_CATALOG_BYTES),
        _read_offline_review_json(Path(args.preflight), MAX_MCP_PREFLIGHT_BYTES),
        _read_offline_review_json(Path(args.bindings), MAX_MCP_BINDINGS_BYTES),
    )


def _run_mcp_api_read_bindings(args: argparse.Namespace) -> None:
    try:
        result = build_mcp_api_read_bindings(*_mcp_api_binding_sources(args))
    except MCPApiReadBindingError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(result, None)


def _run_agent_trace_review(args: argparse.Namespace) -> None:
    trace = _read_offline_review_json(Path(args.trace), MAX_AGENT_TRACE_BYTES)
    try:
        review = build_agent_trace_review(trace)
    except AgentTraceReviewError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(review, None)


def _verify_agent_trace_review(args: argparse.Namespace) -> None:
    trace = _read_offline_review_json(Path(args.trace), MAX_AGENT_TRACE_BYTES)
    review = _read_offline_review_json(
        Path(args.review), MAX_AGENT_TRACE_REVIEW_BYTES,
    )
    try:
        result = verify_agent_trace_review(trace, review)
    except AgentTraceReviewError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(result, None)


def _agent_trace_regression_sources(args: argparse.Namespace) -> tuple[Any, ...]:
    return (
        _read_offline_review_json(Path(args.prior_trace), MAX_AGENT_TRACE_BYTES),
        _read_offline_review_json(Path(args.prior_review), MAX_AGENT_TRACE_REVIEW_BYTES),
        _read_offline_review_json(Path(args.current_trace), MAX_AGENT_TRACE_BYTES),
        _read_offline_review_json(Path(args.current_review), MAX_AGENT_TRACE_REVIEW_BYTES),
    )


def _run_agent_trace_regression(args: argparse.Namespace) -> None:
    try:
        result = build_agent_trace_regression(*_agent_trace_regression_sources(args))
    except AgentTraceRegressionError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(result, None)


def _verify_mcp_api_read_bindings(args: argparse.Namespace) -> None:
    sources = _mcp_api_binding_sources(args)
    plan = _read_offline_review_json(Path(args.plan), MAX_MCP_BINDING_PLAN_BYTES)
    try:
        result = verify_mcp_api_read_bindings(*sources, plan)
    except MCPApiReadBindingError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(result, None)


def _verify_agent_trace_regression(args: argparse.Namespace) -> None:
    sources = _agent_trace_regression_sources(args)
    comparison = _read_offline_review_json(
        Path(args.comparison), MAX_AGENT_TRACE_COMPARISON_BYTES,
    )
    try:
        result = verify_agent_trace_regression(*sources, comparison)
    except AgentTraceRegressionError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(result, None)


def _verify_offline_review(args: argparse.Namespace) -> None:
    request = _read_offline_review_json(Path(args.input), MAX_INPUT_BYTES)
    bundle = _read_offline_review_json(Path(args.bundle), MAX_BUNDLE_BYTES)
    try:
        result = verify_offline_review_bundle(request, bundle)
    except OfflineReviewWorkflowError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(result, None)


def _verify_traffic_api_inventory(args: argparse.Namespace) -> None:
    try:
        with Path(args.inventory).open("rb") as stream:
            inventory_bytes = stream.read(MAX_INVENTORY_JSON_BYTES + 1)
        inventory = load_traffic_api_inventory_json(inventory_bytes)
        raw_observations = _read_offline_review_json(
            Path(args.observations), 32_000_000
        )
        if (
            not isinstance(raw_observations, list)
            or len(raw_observations) > MAX_OBSERVATIONS
        ):
            raise TrafficApiInventoryError("observations must be a bounded JSON list")
        observations = tuple(
            SanitizedApiTrafficObservation.from_dict(item)
            for item in raw_observations
        )
        contract_bundle = None
        if args.contract_bundle is not None:
            contract_bundle = ServiceContractEndpointBundle.from_dict(
                _read_offline_review_json(Path(args.contract_bundle), 16_000_000)
            )
        verify_traffic_api_inventory_from_sources(
            inventory,
            observations=observations,
            contract_bundle=contract_bundle,
        )
    except OSError as exc:
        raise SunderkeyError("Could not read traffic inventory archive") from exc
    except (TrafficApiInventoryError, ServiceContractExtractionError) as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(
        {
            "status": "valid",
            "inventory_sha256": inventory.inventory_sha256,
            "observation_count": len(inventory.observation_sha256),
            "contract_bundle_sha256": inventory.contract_bundle_sha256,
            "verification_scope": "historical_source_replay_only",
            "origin_authentication": "not_verified",
            "authority_effect": "none",
            "network_call_performed": False,
        },
        None,
    )


def _run_offline_review_handoff(args: argparse.Namespace) -> None:
    request = _read_offline_review_json(Path(args.input), MAX_INPUT_BYTES)
    bundle = _read_offline_review_json(Path(args.bundle), MAX_BUNDLE_BYTES)
    try:
        handoff = build_offline_review_handoff(request, bundle)
    except OfflineReviewHandoffError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(handoff, None)


def _verify_offline_review_handoff(args: argparse.Namespace) -> None:
    request = _read_offline_review_json(Path(args.input), MAX_INPUT_BYTES)
    bundle = _read_offline_review_json(Path(args.bundle), MAX_BUNDLE_BYTES)
    handoff = _read_offline_review_json(Path(args.handoff), MAX_HANDOFF_BYTES)
    try:
        result = verify_offline_review_handoff(request, bundle, handoff)
    except OfflineReviewHandoffError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(result, None)


def _read_offline_transition_sources(args: argparse.Namespace) -> tuple[Any, ...]:
    return (
        _read_offline_review_json(Path(args.prior_input), MAX_INPUT_BYTES),
        _read_offline_review_json(Path(args.prior_bundle), MAX_BUNDLE_BYTES),
        _read_offline_review_json(Path(args.prior_handoff), MAX_HANDOFF_BYTES),
        _read_offline_review_json(Path(args.current_input), MAX_INPUT_BYTES),
        _read_offline_review_json(Path(args.current_bundle), MAX_BUNDLE_BYTES),
        _read_offline_review_json(Path(args.current_handoff), MAX_HANDOFF_BYTES),
    )


def _run_offline_review_transition(args: argparse.Namespace) -> None:
    sources = _read_offline_transition_sources(args)
    try:
        transition = build_offline_review_transition(*sources)
    except OfflineReviewTransitionError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(transition, None)


def _verify_offline_review_transition(args: argparse.Namespace) -> None:
    sources = _read_offline_transition_sources(args)
    transition = _read_offline_review_json(
        Path(args.transition), MAX_TRANSITION_BYTES,
    )
    try:
        result = verify_offline_review_transition(*sources, transition)
    except OfflineReviewTransitionError as exc:
        raise SunderkeyError(str(exc)) from exc
    _write_json(result, None)


def build_parser() -> argparse.ArgumentParser:
    parser = _SunderkeyArgumentParser(
        description="Validate and plan SUNDERKEY expert missions"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    registry_parser = subparsers.add_parser(
        "validate-registry",
        help="Validate a versioned expert registry",
    )
    registry_parser.add_argument("--registry", required=True)
    registry_parser.add_argument("--output")
    registry_parser.set_defaults(handler=_validate_registry)

    army_readiness_parser = subparsers.add_parser(
        "army-readiness",
        help=(
            "Assess full-Army capability mapping and qualification "
            "readiness"
        ),
    )
    army_readiness_parser.add_argument("--registry", required=True)
    army_readiness_parser.add_argument(
        "--capabilities",
        required=True,
    )
    army_readiness_parser.add_argument("--policy", required=True)
    army_readiness_parser.add_argument("--output")
    army_readiness_parser.set_defaults(
        handler=_assess_army_readiness
    )

    qualification_coverage_parser = subparsers.add_parser(
        "qualification-coverage",
        help=(
            "Assess full-Army qualification plan coverage and execution "
            "priority"
        ),
    )
    qualification_coverage_parser.add_argument(
        "--registry",
        required=True,
    )
    qualification_coverage_parser.add_argument(
        "--capabilities",
        required=True,
    )
    qualification_coverage_parser.add_argument(
        "--standard",
        required=True,
    )
    qualification_coverage_parser.add_argument(
        "--plans",
        required=True,
    )
    qualification_coverage_parser.add_argument("--output")
    qualification_coverage_parser.set_defaults(
        handler=_assess_qualification_coverage
    )

    qualification_evaluation_parser = subparsers.add_parser(
        "qualification-evaluate",
        help=(
            "Evaluate advisory-only synthetic qualification observations"
        ),
    )
    for option in (
        "registry",
        "capabilities",
        "standard",
        "plans",
        "suite",
        "observations",
    ):
        qualification_evaluation_parser.add_argument(
            f"--{option}",
            required=True,
        )
    qualification_evaluation_parser.add_argument("--output")
    qualification_evaluation_parser.set_defaults(
        handler=_evaluate_qualification
    )

    candidate_inventory_parser = subparsers.add_parser(
        "candidate-inventory",
        help="Assess provider-neutral specialist candidate coverage",
    )
    for option in (
        "registry",
        "capabilities",
        "standard",
        "plans",
        "blueprints",
        "candidates",
    ):
        candidate_inventory_parser.add_argument(
            f"--{option}",
            required=True,
        )
    candidate_inventory_parser.add_argument("--output")
    candidate_inventory_parser.set_defaults(
        handler=_assess_candidate_inventory
    )

    candidate_blueprint_parser = subparsers.add_parser(
        "candidate-blueprint-coverage",
        help="Assess deterministic specialist candidate blueprint coverage",
    )
    for option in (
        "registry",
        "capabilities",
        "standard",
        "plans",
        "blueprints",
    ):
        candidate_blueprint_parser.add_argument(
            f"--{option}",
            required=True,
        )
    candidate_blueprint_parser.add_argument("--output")
    candidate_blueprint_parser.set_defaults(
        handler=_assess_candidate_blueprint_coverage
    )

    candidate_onboarding_parser = subparsers.add_parser(
        "candidate-onboarding",
        help="Validate provider-neutral candidate component bindings",
    )
    for option in (
        "registry",
        "capabilities",
        "standard",
        "plans",
        "blueprints",
        "components",
        "candidates",
    ):
        candidate_onboarding_parser.add_argument(
            f"--{option}",
            required=True,
        )
    candidate_onboarding_parser.add_argument("--output")
    candidate_onboarding_parser.set_defaults(
        handler=_assess_candidate_onboarding
    )

    candidate_preflight_parser = subparsers.add_parser(
        "candidate-preflight",
        help="Validate an unsigned synthetic candidate evaluation submission",
    )
    for option in (
        "registry",
        "capabilities",
        "standard",
        "plans",
        "blueprints",
        "components",
        "candidates",
        "onboarding",
        "suite",
        "submission",
    ):
        candidate_preflight_parser.add_argument(
            f"--{option}",
            required=True,
        )
    candidate_preflight_parser.add_argument("--output")
    candidate_preflight_parser.set_defaults(
        handler=_assess_candidate_evaluation_preflight
    )

    implementation_roadmap_parser = subparsers.add_parser(
        "implementation-roadmap",
        help="Schedule deterministic specialist implementation waves",
    )
    for option in (
        "registry",
        "capabilities",
        "policy",
        "standard",
        "plans",
        "blueprints",
        "components",
        "candidates",
    ):
        implementation_roadmap_parser.add_argument(
            f"--{option}",
            required=True,
        )
    implementation_roadmap_parser.add_argument("--output")
    implementation_roadmap_parser.set_defaults(
        handler=_assess_specialist_implementation_roadmap
    )

    capability_roadmap_parser = subparsers.add_parser(
        "capability-roadmap",
        help="Verify the active capability roadmap and project package readiness",
    )
    capability_roadmap_parser.add_argument("--roadmap", required=True)
    capability_roadmap_parser.add_argument(
        "--completed-package-id",
        action="append",
        default=[],
    )
    capability_roadmap_parser.add_argument("--output")
    capability_roadmap_parser.set_defaults(handler=_assess_capability_roadmap)

    implementation_work_packages_parser = subparsers.add_parser(
        "implementation-work-packages",
        help="Build domain commander implementation task packages",
    )
    for option in (
        "registry",
        "capabilities",
        "policy",
        "standard",
        "plans",
        "blueprints",
        "components",
        "candidates",
        "roadmap",
    ):
        implementation_work_packages_parser.add_argument(
            f"--{option}",
            required=True,
        )
    implementation_work_packages_parser.add_argument("--output")
    implementation_work_packages_parser.set_defaults(
        handler=_assess_implementation_work_packages
    )

    implementation_wave_package_parser = subparsers.add_parser(
        "implementation-wave-package",
        help="Select one exact domain commander wave package",
    )
    implementation_wave_package_parser.add_argument(
        "--packages",
        required=True,
    )
    implementation_wave_package_parser.add_argument(
        "--wave-id",
        required=True,
    )
    implementation_wave_package_parser.add_argument("--output")
    implementation_wave_package_parser.set_defaults(
        handler=_select_implementation_wave_package
    )

    qualification_authority_dossier_parser = subparsers.add_parser(
        "qualification-authority-dossier",
        help="Build the pending D008 qualification authority decision dossier",
    )
    for option in (
        "registry",
        "capabilities",
        "standard",
        "roadmap",
        "packages",
    ):
        qualification_authority_dossier_parser.add_argument(
            f"--{option}",
            required=True,
        )
    qualification_authority_dossier_parser.add_argument("--output")
    qualification_authority_dossier_parser.set_defaults(
        handler=_assess_qualification_authority_decision
    )

    qualification_authority_decision_parser = subparsers.add_parser(
        "qualification-authority-decision",
        help="Record the owner-approved D008 qualification authority bundle",
    )
    qualification_authority_decision_parser.add_argument(
        "--dossier",
        required=True,
    )
    qualification_authority_decision_parser.add_argument("--output")
    qualification_authority_decision_parser.set_defaults(
        handler=_record_qualification_authority_decision
    )

    candidate_enrollment_dossier_parser = subparsers.add_parser(
        "candidate-enrollment-dossier",
        help="Build the pending D009 candidate enrollment decision dossier",
    )
    for option in (
        "registry",
        "capabilities",
        "standard",
        "authority-decision",
    ):
        candidate_enrollment_dossier_parser.add_argument(
            f"--{option}",
            required=True,
        )
    candidate_enrollment_dossier_parser.add_argument("--output")
    candidate_enrollment_dossier_parser.set_defaults(
        handler=_assess_candidate_enrollment_decision
    )

    candidate_enrollment_template_parser = subparsers.add_parser(
        "candidate-enrollment-decision-template-create",
        help="Prepare the recommended D009 bundle for explicit owner review",
    )
    candidate_enrollment_template_parser.add_argument("--dossier", required=True)
    candidate_enrollment_template_parser.add_argument("--output", required=True)
    candidate_enrollment_template_parser.set_defaults(
        handler=_candidate_enrollment_decision_template_create
    )

    candidate_enrollment_record_parser = subparsers.add_parser(
        "candidate-enrollment-decision-record",
        help="Record an explicit owner-selected D009 architecture bundle",
    )
    candidate_enrollment_record_parser.add_argument("--dossier", required=True)
    candidate_enrollment_record_parser.add_argument("--submission", required=True)
    candidate_enrollment_record_parser.add_argument("--output", required=True)
    candidate_enrollment_record_parser.set_defaults(
        handler=_candidate_enrollment_decision_record
    )

    candidate_enrollment_record_verify_parser = subparsers.add_parser(
        "candidate-enrollment-decision-record-verify",
        help="Verify a D009 decision record against its exact dossier",
    )
    candidate_enrollment_record_verify_parser.add_argument(
        "--dossier",
        required=True,
    )
    candidate_enrollment_record_verify_parser.add_argument(
        "--record",
        required=True,
    )
    candidate_enrollment_record_verify_parser.add_argument("--output")
    candidate_enrollment_record_verify_parser.set_defaults(
        handler=_verify_candidate_enrollment_decision_record
    )

    candidate_enrollment_deployment_parser = subparsers.add_parser(
        "candidate-enrollment-deployment-prepare",
        help="Prepare the offline deployment-owned D009 enrollment ceremonies",
    )
    candidate_enrollment_deployment_parser.add_argument(
        "--implementation",
        required=True,
    )
    candidate_enrollment_deployment_parser.add_argument("--output")
    candidate_enrollment_deployment_parser.set_defaults(
        handler=_prepare_candidate_enrollment_deployment
    )

    candidate_enrollment_activation_dossier_parser = subparsers.add_parser(
        "candidate-enrollment-activation-dossier",
        help="Build the pending D011 checkpoint custody and activation dossier",
    )
    for option in (
        "d009-decision",
        "implementation",
        "preparation",
        "verification-receipt-schema",
    ):
        candidate_enrollment_activation_dossier_parser.add_argument(
            f"--{option}",
            required=True,
        )
    candidate_enrollment_activation_dossier_parser.add_argument("--output")
    candidate_enrollment_activation_dossier_parser.set_defaults(
        handler=_build_candidate_enrollment_activation_dossier
    )

    candidate_enrollment_activation_template_parser = subparsers.add_parser(
        "candidate-enrollment-activation-decision-template-create",
        help="Prepare the recommended D011 bundle for explicit owner review",
    )
    candidate_enrollment_activation_template_parser.add_argument(
        "--dossier", required=True
    )
    candidate_enrollment_activation_template_parser.add_argument(
        "--output", required=True
    )
    candidate_enrollment_activation_template_parser.set_defaults(
        handler=_candidate_enrollment_activation_decision_template_create
    )

    candidate_enrollment_activation_record_parser = subparsers.add_parser(
        "candidate-enrollment-activation-decision-record",
        help="Record an explicit owner-selected D011 architecture bundle",
    )
    candidate_enrollment_activation_record_parser.add_argument(
        "--dossier", required=True
    )
    candidate_enrollment_activation_record_parser.add_argument(
        "--submission", required=True
    )
    candidate_enrollment_activation_record_parser.add_argument(
        "--output", required=True
    )
    candidate_enrollment_activation_record_parser.set_defaults(
        handler=_candidate_enrollment_activation_decision_record
    )

    candidate_enrollment_activation_verify_parser = subparsers.add_parser(
        "candidate-enrollment-activation-decision-record-verify",
        help="Verify a D011 decision record against its exact dossier",
    )
    candidate_enrollment_activation_verify_parser.add_argument(
        "--dossier", required=True
    )
    candidate_enrollment_activation_verify_parser.add_argument(
        "--record", required=True
    )
    candidate_enrollment_activation_verify_parser.add_argument("--output")
    candidate_enrollment_activation_verify_parser.set_defaults(
        handler=_verify_candidate_enrollment_activation_decision_record
    )

    candidate_enrollment_release_policy_parser = subparsers.add_parser(
        "candidate-enrollment-release-policy",
        help="Build the approved D011 checkpoint and release contract",
    )
    candidate_enrollment_release_policy_parser.add_argument(
        "--decision", required=True
    )
    candidate_enrollment_release_policy_parser.add_argument("--output")
    candidate_enrollment_release_policy_parser.set_defaults(
        handler=_build_candidate_enrollment_release_policy
    )

    candidate_enrollment_release_policy_verify_parser = subparsers.add_parser(
        "candidate-enrollment-release-policy-verify",
        help="Verify the checkpoint and release contract against D011",
    )
    candidate_enrollment_release_policy_verify_parser.add_argument(
        "--decision", required=True
    )
    candidate_enrollment_release_policy_verify_parser.add_argument(
        "--policy", required=True
    )
    candidate_enrollment_release_policy_verify_parser.add_argument("--output")
    candidate_enrollment_release_policy_verify_parser.set_defaults(
        handler=_verify_candidate_enrollment_release_policy
    )

    candidate_enrollment_canary_parser = subparsers.add_parser(
        "candidate-enrollment-canary-prepare",
        help="Build the D011 single-candidate canary preparation packet",
    )
    candidate_enrollment_canary_verify_parser = subparsers.add_parser(
        "candidate-enrollment-canary-verify",
        help="Verify the D011 canary preparation against its exact inputs",
    )
    for canary_parser in (
        candidate_enrollment_canary_parser,
        candidate_enrollment_canary_verify_parser,
    ):
        canary_parser.add_argument("--decision", required=True)
        canary_parser.add_argument("--policy", required=True)
        canary_parser.add_argument("--normal-completion-schema", required=True)
        canary_parser.add_argument("--recovery-completion-schema", required=True)
        canary_parser.add_argument("--output")
    candidate_enrollment_canary_verify_parser.add_argument("--packet", required=True)
    candidate_enrollment_canary_parser.set_defaults(
        handler=_build_candidate_enrollment_canary_preparation
    )
    candidate_enrollment_canary_verify_parser.set_defaults(
        handler=_verify_candidate_enrollment_canary_preparation
    )

    candidate_enrollment_implementation_parser = subparsers.add_parser(
        "candidate-enrollment-activation-implementation-report",
        help="Build the D011 contract implementation completion report",
    )
    candidate_enrollment_implementation_verify_parser = subparsers.add_parser(
        "candidate-enrollment-activation-implementation-verify",
        help="Verify the D011 implementation report against its exact inputs",
    )
    for implementation_parser in (
        candidate_enrollment_implementation_parser,
        candidate_enrollment_implementation_verify_parser,
    ):
        implementation_parser.add_argument("--decision", required=True)
        implementation_parser.add_argument("--policy", required=True)
        implementation_parser.add_argument("--canary", required=True)
        implementation_parser.add_argument("--output")
    candidate_enrollment_implementation_verify_parser.add_argument(
        "--report", required=True
    )
    candidate_enrollment_implementation_parser.set_defaults(
        handler=_build_candidate_enrollment_activation_implementation
    )
    candidate_enrollment_implementation_verify_parser.set_defaults(
        handler=_verify_candidate_enrollment_activation_implementation
    )

    candidate_enrollment_production_custody_parser = subparsers.add_parser(
        "candidate-enrollment-production-custody-dossier",
        help="Build the pending D012 production custody decision dossier",
    )
    candidate_enrollment_production_custody_parser.add_argument(
        "--implementation", required=True
    )
    candidate_enrollment_production_custody_parser.add_argument(
        "--canary", required=True
    )
    candidate_enrollment_production_custody_parser.add_argument("--output")
    candidate_enrollment_production_custody_parser.set_defaults(
        handler=_build_candidate_enrollment_production_custody_dossier
    )

    candidate_enrollment_production_custody_template_parser = subparsers.add_parser(
        "candidate-enrollment-production-custody-decision-template-create",
        help="Prepare the recommended D012 bundle for explicit owner review",
    )
    candidate_enrollment_production_custody_template_parser.add_argument(
        "--dossier", required=True
    )
    candidate_enrollment_production_custody_template_parser.add_argument(
        "--output", required=True
    )
    candidate_enrollment_production_custody_template_parser.set_defaults(
        handler=_candidate_enrollment_production_custody_decision_template_create
    )

    candidate_enrollment_production_custody_record_parser = subparsers.add_parser(
        "candidate-enrollment-production-custody-decision-record",
        help="Record an explicit owner-selected D012 production custody bundle",
    )
    candidate_enrollment_production_custody_record_parser.add_argument(
        "--dossier", required=True
    )
    candidate_enrollment_production_custody_record_parser.add_argument(
        "--submission", required=True
    )
    candidate_enrollment_production_custody_record_parser.add_argument(
        "--output", required=True
    )
    candidate_enrollment_production_custody_record_parser.set_defaults(
        handler=_candidate_enrollment_production_custody_decision_record
    )

    candidate_enrollment_production_custody_verify_parser = subparsers.add_parser(
        "candidate-enrollment-production-custody-decision-record-verify",
        help="Verify a D012 decision record against its exact dossier",
    )
    candidate_enrollment_production_custody_verify_parser.add_argument(
        "--dossier", required=True
    )
    candidate_enrollment_production_custody_verify_parser.add_argument(
        "--record", required=True
    )
    candidate_enrollment_production_custody_verify_parser.add_argument("--output")
    candidate_enrollment_production_custody_verify_parser.set_defaults(
        handler=_verify_candidate_enrollment_production_custody_decision_record
    )

    candidate_enrollment_worksheet_parser = subparsers.add_parser(
        "candidate-enrollment-deployment-template-create",
        help="Create an editable public-input worksheet for a D009 deployment",
    )
    candidate_enrollment_worksheet_parser.add_argument(
        "--preparation",
        required=True,
    )
    candidate_enrollment_worksheet_parser.add_argument("--output", required=True)
    candidate_enrollment_worksheet_parser.set_defaults(
        handler=_create_candidate_enrollment_deployment_worksheet
    )

    candidate_enrollment_preflight_parser = subparsers.add_parser(
        "candidate-enrollment-deployment-preflight",
        help="Assess worksheet completeness without granting enrollment trust",
    )
    candidate_enrollment_preflight_parser.add_argument(
        "--preparation",
        required=True,
    )
    candidate_enrollment_preflight_parser.add_argument("--worksheet", required=True)
    candidate_enrollment_preflight_parser.add_argument("--output")
    candidate_enrollment_preflight_parser.set_defaults(
        handler=_preflight_candidate_enrollment_deployment_inputs
    )

    candidate_enrollment_verification_parser = subparsers.add_parser(
        "candidate-enrollment-deployment-verify",
        help="Verify the complete offline D009 trust chain and derive a checkpoint",
    )
    for option in (
        "preparation",
        "worksheet",
        "preflight",
        "context",
        "registry",
        "capabilities",
        "standard",
        "d008-decision",
        "d009-decision",
        "policy",
        "authorization",
        "control-credential",
        "assurance-credential",
        "catalog",
    ):
        candidate_enrollment_verification_parser.add_argument(
            f"--{option}",
            required=True,
        )
    candidate_enrollment_verification_parser.add_argument("--output", required=True)
    candidate_enrollment_verification_parser.set_defaults(
        handler=_verify_candidate_enrollment_deployment_artifacts
    )

    candidate_enrollment_receipt_verify_parser = subparsers.add_parser(
        "candidate-enrollment-deployment-receipt-verify",
        help="Re-run every source check for a D009 verification receipt",
    )
    for option in (
        "preparation",
        "worksheet",
        "preflight",
        "context",
        "registry",
        "capabilities",
        "standard",
        "d008-decision",
        "d009-decision",
        "policy",
        "authorization",
        "control-credential",
        "assurance-credential",
        "catalog",
        "receipt",
    ):
        candidate_enrollment_receipt_verify_parser.add_argument(
            f"--{option}",
            required=True,
        )
    candidate_enrollment_receipt_verify_parser.add_argument("--output")
    candidate_enrollment_receipt_verify_parser.set_defaults(
        handler=_verify_candidate_enrollment_deployment_receipt
    )

    collaboration_authority_dossier_parser = subparsers.add_parser(
        "collaboration-authority-dossier",
        help="Build the pending D001-D005 collaboration authority dossier",
    )
    for option in ("registry", "capabilities", "policy"):
        collaboration_authority_dossier_parser.add_argument(
            f"--{option}",
            required=True,
        )
    collaboration_authority_dossier_parser.add_argument("--output")
    collaboration_authority_dossier_parser.set_defaults(
        handler=_assess_collaboration_authority_decisions
    )

    collaboration_authority_template_parser = subparsers.add_parser(
        "collaboration-authority-decision-template-create",
        help="Prepare the recommended D001-D005 bundle for explicit owner review",
    )
    collaboration_authority_template_parser.add_argument("--dossier", required=True)
    collaboration_authority_template_parser.add_argument("--output", required=True)
    collaboration_authority_template_parser.set_defaults(
        handler=_collaboration_authority_decision_template_create
    )

    collaboration_authority_record_parser = subparsers.add_parser(
        "collaboration-authority-decision-record",
        help="Record an explicit owner-selected D001-D005 authority bundle",
    )
    collaboration_authority_record_parser.add_argument("--dossier", required=True)
    collaboration_authority_record_parser.add_argument("--submission", required=True)
    collaboration_authority_record_parser.add_argument("--output", required=True)
    collaboration_authority_record_parser.set_defaults(
        handler=_collaboration_authority_decision_record
    )

    collaboration_authority_verify_parser = subparsers.add_parser(
        "collaboration-authority-decision-record-verify",
        help="Verify a D001-D005 decision record against its exact dossier",
    )
    collaboration_authority_verify_parser.add_argument("--dossier", required=True)
    collaboration_authority_verify_parser.add_argument("--record", required=True)
    collaboration_authority_verify_parser.add_argument("--output")
    collaboration_authority_verify_parser.set_defaults(
        handler=_verify_collaboration_authority_decision_record
    )

    collaboration_reconfiguration_policy_parser = subparsers.add_parser(
        "collaboration-reconfiguration-policy",
        help="Build the approved but inactive D001-D005 authority policy",
    )
    collaboration_reconfiguration_policy_verify_parser = subparsers.add_parser(
        "collaboration-reconfiguration-policy-verify",
        help="Verify the D001-D005 authority policy against its decision",
    )
    for policy_parser in (
        collaboration_reconfiguration_policy_parser,
        collaboration_reconfiguration_policy_verify_parser,
    ):
        policy_parser.add_argument("--decision", required=True)
        policy_parser.add_argument("--output")
    collaboration_reconfiguration_policy_verify_parser.add_argument(
        "--policy", required=True
    )
    collaboration_reconfiguration_policy_parser.set_defaults(
        handler=_build_collaboration_reconfiguration_policy
    )
    collaboration_reconfiguration_policy_verify_parser.set_defaults(
        handler=_verify_collaboration_reconfiguration_policy
    )

    assemble_parser = subparsers.add_parser(
        "assemble",
        help="Assemble a deterministic Joint Mission Cell",
    )
    assemble_parser.add_argument("--registry", required=True)
    assemble_parser.add_argument("--mission", required=True)
    assemble_parser.add_argument("--output")
    assemble_parser.set_defaults(handler=_assemble)

    collaboration_parser = subparsers.add_parser(
        "plan-collaboration",
        help="Build a deterministic mission collaboration plan",
    )
    collaboration_parser.add_argument("--registry", required=True)
    collaboration_parser.add_argument("--mission", required=True)
    collaboration_parser.add_argument("--output")
    collaboration_parser.set_defaults(handler=_plan_collaboration)

    collaboration_activation_parser = subparsers.add_parser(
        "collaboration-activate-authenticated",
        help=(
            "Authenticate and durably activate one exact "
            "collaboration plan"
        ),
    )
    collaboration_activation_parser.add_argument(
        "--store",
        required=True,
    )
    collaboration_activation_parser.add_argument(
        "--registry",
        required=True,
    )
    collaboration_activation_parser.add_argument(
        "--plan",
        required=True,
    )
    collaboration_activation_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    collaboration_activation_parser.add_argument("--output")
    collaboration_activation_parser.set_defaults(
        handler=_activate_collaboration_authenticated
    )

    collaboration_status_parser = subparsers.add_parser(
        "collaboration-status",
        help="Show a mission's verified collaboration activation",
    )
    collaboration_status_parser.add_argument(
        "--store",
        required=True,
    )
    collaboration_status_parser.add_argument(
        "--registry",
        required=True,
    )
    collaboration_status_parser.add_argument(
        "--mission-id",
        required=True,
    )
    collaboration_status_parser.add_argument("--output")
    collaboration_status_parser.set_defaults(
        handler=_show_collaboration_status
    )

    collaboration_replacement_readiness_parser = subparsers.add_parser(
        "collaboration-plan-replacement-readiness",
        help="Derive exact replacement blockers and operations without changing state",
    )
    collaboration_replacement_prepare_parser = subparsers.add_parser(
        "collaboration-plan-replacement-prepare",
        help="Prepare one exact replacement attempt for source-derived signed authorities",
    )
    for replacement_parser in (
        collaboration_replacement_readiness_parser,
        collaboration_replacement_prepare_parser,
    ):
        replacement_parser.add_argument("--store", required=True)
        replacement_parser.add_argument("--registry", required=True)
        replacement_parser.add_argument("--authority-policy", required=True)
        replacement_parser.add_argument("--replacement-plan", required=True)
        replacement_parser.add_argument("--mapping-intents", required=True)
        replacement_parser.add_argument("--independent-control-profile-id")
        replacement_parser.add_argument(
            "--independent-assurance-profile-id",
            required=True,
        )
        replacement_parser.add_argument(
            "--second-control-profile-id",
            required=True,
        )
    collaboration_replacement_readiness_parser.add_argument("--output")
    collaboration_replacement_prepare_parser.add_argument(
        "--output", required=True
    )
    collaboration_replacement_prepare_parser.add_argument(
        "--issued-at", required=True
    )
    collaboration_replacement_prepare_parser.add_argument(
        "--expires-at", required=True
    )
    collaboration_replacement_readiness_parser.set_defaults(
        handler=_assess_collaboration_plan_replacement_readiness
    )
    collaboration_replacement_prepare_parser.set_defaults(
        handler=_prepare_collaboration_plan_replacement
    )

    collaboration_replacement_execute_parser = subparsers.add_parser(
        "collaboration-plan-replacement-execute",
        help="Authenticate and atomically commit one exact prepared replacement",
    )
    collaboration_replacement_execute_parser.add_argument(
        "--store", required=True
    )
    collaboration_replacement_execute_parser.add_argument(
        "--registry", required=True
    )
    collaboration_replacement_execute_parser.add_argument(
        "--authority-policy", required=True
    )
    collaboration_replacement_execute_parser.add_argument(
        "--preparation", required=True
    )
    collaboration_replacement_execute_parser.add_argument(
        "--credentials", required=True
    )
    collaboration_replacement_execute_parser.add_argument("--output")
    collaboration_replacement_execute_parser.set_defaults(
        handler=_execute_collaboration_plan_replacement
    )

    reviewer_admission_prepare_parser = subparsers.add_parser(
        "collaboration-plan-replacement-reviewer-admission-prepare",
        help="Capture one explicit reviewer request without accepting its signed grant",
    )
    reviewer_admission_intents_parser = subparsers.add_parser(
        "collaboration-plan-replacement-reviewer-admission-approval-intents",
        help="Export unsigned approval intents without verifying approver assignments",
    )
    reviewer_admission_admit_parser = subparsers.add_parser(
        "collaboration-plan-replacement-reviewer-admission-admit",
        help="Atomically admit one reviewer using two externally signed assertions",
    )
    reviewer_admission_show_parser = subparsers.add_parser(
        "collaboration-plan-replacement-reviewer-admission-show",
        help="Inspect historical reviewer custody without establishing current authority",
    )
    for reviewer_admission_parser in (
        reviewer_admission_prepare_parser,
        reviewer_admission_admit_parser,
        reviewer_admission_show_parser,
    ):
        reviewer_admission_parser.add_argument("--store", required=True)
        reviewer_admission_parser.add_argument("--registry", required=True)
    for reviewer_admission_parser in (
        reviewer_admission_prepare_parser,
        reviewer_admission_show_parser,
    ):
        reviewer_admission_parser.add_argument("--mission-id", required=True)
        reviewer_admission_parser.add_argument("--admission-id", required=True)
    reviewer_admission_prepare_parser.add_argument(
        "--reviewer-scope-grant", dest="scope_grant", required=True
    )
    for option in ("reviewer-issuer", "reviewer-subject", "issued-at", "not-before", "expires-at"):
        reviewer_admission_prepare_parser.add_argument(f"--{option}", required=True)
    reviewer_admission_prepare_parser.add_argument(
        "--role", choices=tuple(REVIEWER_OPERATIONS), required=True
    )
    reviewer_admission_prepare_parser.add_argument("--output", required=True)
    reviewer_admission_prepare_parser.set_defaults(
        handler=_prepare_plan_replacement_reviewer_admission
    )
    for option in (
        "request",
        "mission-owner-profile-id",
        "independent-control-profile-id",
        "output",
    ):
        reviewer_admission_intents_parser.add_argument(f"--{option}", required=True)
    reviewer_admission_intents_parser.set_defaults(
        handler=_plan_replacement_reviewer_admission_approval_intents
    )
    for option in ("request", "mission-owner-assertion", "independent-control-assertion"):
        reviewer_admission_admit_parser.add_argument(f"--{option}", required=True)
    reviewer_admission_admit_parser.set_defaults(handler=_admit_plan_replacement_reviewer)
    reviewer_admission_show_parser.set_defaults(handler=_show_plan_replacement_reviewer_admission)

    repository_authentication_show_parser = subparsers.add_parser(
        "provider-evidence-repository-authentication-show",
        help="Inspect historical repository report custody without establishing current authority",
    )
    for option in ("store", "registry", "authentication-id"):
        repository_authentication_show_parser.add_argument(f"--{option}", required=True)
    repository_authentication_show_parser.set_defaults(
        handler=_show_provider_evidence_repository_authentication
    )

    collaboration_policy_commit_parser = subparsers.add_parser(
        "collaboration-mission-policy-commit",
        help=(
            "Authenticate and atomically commit one mission "
            "reconfiguration policy"
        ),
    )
    collaboration_policy_commit_parser.add_argument(
        "--store",
        required=True,
    )
    collaboration_policy_commit_parser.add_argument(
        "--registry",
        required=True,
    )
    collaboration_policy_commit_parser.add_argument(
        "--authority-policy",
        required=True,
    )
    collaboration_policy_commit_parser.add_argument(
        "--mission-policy",
        required=True,
    )
    collaboration_policy_commit_parser.add_argument(
        "--mission-owner-assertion",
        required=True,
    )
    collaboration_policy_commit_parser.add_argument(
        "--independent-control-assertion",
        required=True,
    )
    collaboration_policy_commit_parser.add_argument("--output")
    collaboration_policy_commit_parser.set_defaults(
        handler=_commit_collaboration_mission_policy
    )

    collaboration_policy_status_parser = subparsers.add_parser(
        "collaboration-mission-policy-status",
        help="Show a verified committed mission reconfiguration policy",
    )
    collaboration_policy_status_parser.add_argument(
        "--store",
        required=True,
    )
    collaboration_policy_status_parser.add_argument(
        "--registry",
        required=True,
    )
    collaboration_policy_status_parser.add_argument(
        "--mission-id",
        required=True,
    )
    collaboration_policy_status_parser.add_argument(
        "--policy-version",
        type=int,
    )
    collaboration_policy_status_parser.add_argument("--output")
    collaboration_policy_status_parser.set_defaults(
        handler=_show_collaboration_mission_policy
    )

    collaboration_ownership_preflight_parser = subparsers.add_parser(
        "collaboration-ownership-transition-preflight",
        help=(
            "Verify one initial ownership delegation against the "
            "committed mission policy and live work fence"
        ),
    )
    collaboration_ownership_preflight_parser.add_argument(
        "--store",
        required=True,
    )
    collaboration_ownership_preflight_parser.add_argument(
        "--registry",
        required=True,
    )
    collaboration_ownership_preflight_parser.add_argument(
        "--ownership-entry",
        required=True,
    )
    collaboration_ownership_preflight_parser.add_argument("--output")
    collaboration_ownership_preflight_parser.set_defaults(
        handler=_preflight_collaboration_ownership_transition
    )

    collaboration_ownership_commit_parser = subparsers.add_parser(
        "collaboration-ownership-transition-commit",
        help=(
            "Authenticate and atomically commit one verified ownership "
            "transition"
        ),
    )
    collaboration_ownership_commit_parser.add_argument(
        "--store",
        required=True,
    )
    collaboration_ownership_commit_parser.add_argument(
        "--registry",
        required=True,
    )
    collaboration_ownership_commit_parser.add_argument(
        "--preflight",
        required=True,
    )
    collaboration_ownership_commit_parser.add_argument(
        "--current-owner-assertion",
        required=True,
    )
    collaboration_ownership_commit_parser.add_argument(
        "--proposed-owner-assertion",
        required=True,
    )
    collaboration_ownership_commit_parser.add_argument(
        "--independent-control-assertion",
        required=True,
    )
    collaboration_ownership_commit_parser.add_argument("--output")
    collaboration_ownership_commit_parser.set_defaults(
        handler=_commit_collaboration_ownership_transition
    )

    collaboration_ownership_status_parser = subparsers.add_parser(
        "collaboration-ownership-transition-status",
        help="Show a verified committed ownership transition",
    )
    collaboration_ownership_status_parser.add_argument(
        "--store",
        required=True,
    )
    collaboration_ownership_status_parser.add_argument(
        "--registry",
        required=True,
    )
    collaboration_ownership_status_parser.add_argument(
        "--mission-id",
        required=True,
    )
    collaboration_ownership_status_parser.add_argument(
        "--work-item-id",
        required=True,
    )
    collaboration_ownership_status_parser.add_argument("--entry-id")
    collaboration_ownership_status_parser.add_argument("--output")
    collaboration_ownership_status_parser.set_defaults(
        handler=_show_collaboration_ownership_transition
    )

    privileged_reassignment_preflight_parser = subparsers.add_parser(
        "collaboration-ownership-privileged-reassignment-preflight",
        help=(
            "Verify one privileged ownership reassignment against the "
            "committed policy, chain, registry role, and live work fence"
        ),
    )
    privileged_reassignment_preflight_parser.add_argument(
        "--store",
        required=True,
    )
    privileged_reassignment_preflight_parser.add_argument(
        "--registry",
        required=True,
    )
    privileged_reassignment_preflight_parser.add_argument(
        "--ownership-entry",
        required=True,
    )
    privileged_reassignment_preflight_parser.add_argument("--output")
    privileged_reassignment_preflight_parser.set_defaults(
        handler=_preflight_collaboration_ownership_privileged_reassignment
    )

    privileged_reassignment_commit_parser = subparsers.add_parser(
        "collaboration-ownership-privileged-reassignment-commit",
        help=(
            "Authenticate and atomically commit one privileged ownership "
            "reassignment"
        ),
    )
    privileged_reassignment_commit_parser.add_argument(
        "--store",
        required=True,
    )
    privileged_reassignment_commit_parser.add_argument(
        "--registry",
        required=True,
    )
    privileged_reassignment_commit_parser.add_argument(
        "--preflight",
        required=True,
    )
    privileged_reassignment_commit_parser.add_argument(
        "--current-owner-assertion",
        required=True,
    )
    privileged_reassignment_commit_parser.add_argument(
        "--proposed-owner-assertion",
        required=True,
    )
    privileged_reassignment_commit_parser.add_argument(
        "--independent-control-assertion",
        required=True,
    )
    privileged_reassignment_commit_parser.add_argument(
        "--second-authority-assertion",
    )
    privileged_reassignment_commit_parser.add_argument("--output")
    privileged_reassignment_commit_parser.set_defaults(
        handler=_commit_collaboration_ownership_privileged_reassignment
    )

    privileged_reassignment_status_parser = subparsers.add_parser(
        "collaboration-ownership-privileged-reassignment-status",
        help="Show a verified committed privileged ownership reassignment",
    )
    privileged_reassignment_status_parser.add_argument(
        "--store",
        required=True,
    )
    privileged_reassignment_status_parser.add_argument(
        "--registry",
        required=True,
    )
    privileged_reassignment_status_parser.add_argument(
        "--mission-id",
        required=True,
    )
    privileged_reassignment_status_parser.add_argument(
        "--work-item-id",
        required=True,
    )
    privileged_reassignment_status_parser.add_argument("--entry-id")
    privileged_reassignment_status_parser.add_argument("--output")
    privileged_reassignment_status_parser.set_defaults(
        handler=_show_collaboration_ownership_privileged_reassignment
    )

    ownership_revocation_preflight_parser = subparsers.add_parser(
        "collaboration-ownership-revocation-preflight",
        help=(
            "Verify one independent Control ownership revocation against "
            "the committed chain and live work fence"
        ),
    )
    ownership_revocation_preflight_parser.add_argument(
        "--store",
        required=True,
    )
    ownership_revocation_preflight_parser.add_argument(
        "--registry",
        required=True,
    )
    ownership_revocation_preflight_parser.add_argument(
        "--revocation",
        required=True,
    )
    ownership_revocation_preflight_parser.add_argument("--output")
    ownership_revocation_preflight_parser.set_defaults(
        handler=_preflight_collaboration_ownership_revocation
    )

    ownership_revocation_commit_parser = subparsers.add_parser(
        "collaboration-ownership-revocation-commit",
        help=(
            "Authenticate and atomically commit one independent Control "
            "ownership revocation"
        ),
    )
    ownership_revocation_commit_parser.add_argument(
        "--store",
        required=True,
    )
    ownership_revocation_commit_parser.add_argument(
        "--registry",
        required=True,
    )
    ownership_revocation_commit_parser.add_argument(
        "--preflight",
        required=True,
    )
    ownership_revocation_commit_parser.add_argument(
        "--planned-owner-assertion",
        required=True,
    )
    ownership_revocation_commit_parser.add_argument(
        "--independent-control-assertion",
        required=True,
    )
    ownership_revocation_commit_parser.add_argument("--output")
    ownership_revocation_commit_parser.set_defaults(
        handler=_commit_collaboration_ownership_revocation
    )

    ownership_revocation_status_parser = subparsers.add_parser(
        "collaboration-ownership-revocation-status",
        help="Show a verified committed ownership revocation",
    )
    ownership_revocation_status_parser.add_argument(
        "--store",
        required=True,
    )
    ownership_revocation_status_parser.add_argument(
        "--registry",
        required=True,
    )
    ownership_revocation_status_parser.add_argument(
        "--mission-id",
        required=True,
    )
    ownership_revocation_status_parser.add_argument(
        "--work-item-id",
        required=True,
    )
    ownership_revocation_status_parser.add_argument("--entry-id")
    ownership_revocation_status_parser.add_argument("--output")
    ownership_revocation_status_parser.set_defaults(
        handler=_show_collaboration_ownership_revocation
    )

    work_claim_parser = subparsers.add_parser(
        "work-claim-authenticated",
        help="Claim one ready work item as its planned owner",
    )
    work_claim_parser.add_argument("--store", required=True)
    work_claim_parser.add_argument("--registry", required=True)
    work_claim_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    work_claim_parser.add_argument("--mission-id", required=True)
    work_claim_parser.add_argument("--work-item-id", required=True)
    work_claim_parser.add_argument(
        "--expected-generation",
        type=int,
        required=True,
    )
    work_claim_parser.add_argument("--output")
    work_claim_parser.set_defaults(
        handler=_claim_work_item_authenticated
    )

    work_renew_parser = subparsers.add_parser(
        "work-renew-authenticated",
        help="Renew one active owner lease",
    )
    work_renew_parser.add_argument("--store", required=True)
    work_renew_parser.add_argument("--registry", required=True)
    work_renew_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    work_renew_parser.add_argument("--mission-id", required=True)
    work_renew_parser.add_argument("--work-item-id", required=True)
    work_renew_parser.add_argument(
        "--claim-generation",
        type=int,
        required=True,
    )
    work_renew_parser.add_argument(
        "--previous-transition-id",
        required=True,
    )
    work_renew_parser.add_argument(
        "--expected-lease-expires-at",
        required=True,
    )
    work_renew_parser.add_argument("--output")
    work_renew_parser.set_defaults(
        handler=_renew_work_item_authenticated
    )

    work_release_parser = subparsers.add_parser(
        "work-release-authenticated",
        help="Release one active owner lease with a reason",
    )
    work_release_parser.add_argument("--store", required=True)
    work_release_parser.add_argument("--registry", required=True)
    work_release_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    work_release_parser.add_argument("--mission-id", required=True)
    work_release_parser.add_argument(
        "--work-item-id",
        required=True,
    )
    work_release_parser.add_argument(
        "--claim-generation",
        type=int,
        required=True,
    )
    work_release_parser.add_argument(
        "--previous-transition-id",
        required=True,
    )
    work_release_parser.add_argument(
        "--expected-lease-expires-at",
        required=True,
    )
    work_release_parser.add_argument("--reason-code", required=True)
    work_release_parser.add_argument("--reason", required=True)
    work_release_parser.add_argument("--output")
    work_release_parser.set_defaults(
        handler=_release_work_item_authenticated
    )

    work_complete_parser = subparsers.add_parser(
        "work-complete-authenticated",
        help="Complete one owner lease with result bindings",
    )
    work_complete_parser.add_argument("--store", required=True)
    work_complete_parser.add_argument("--registry", required=True)
    work_complete_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    work_complete_parser.add_argument("--mission-id", required=True)
    work_complete_parser.add_argument(
        "--work-item-id",
        required=True,
    )
    work_complete_parser.add_argument(
        "--claim-generation",
        type=int,
        required=True,
    )
    work_complete_parser.add_argument(
        "--previous-transition-id",
        required=True,
    )
    work_complete_parser.add_argument(
        "--expected-lease-expires-at",
        required=True,
    )
    work_complete_parser.add_argument("--result-id", required=True)
    work_complete_parser.add_argument(
        "--result-sha256",
        required=True,
    )
    work_complete_parser.add_argument(
        "--evidence-manifest-sha256",
        required=True,
    )
    work_complete_parser.add_argument("--output")
    work_complete_parser.set_defaults(
        handler=_complete_work_item_authenticated
    )

    work_status_parser = subparsers.add_parser(
        "work-status",
        help="Show verified effective work item state",
    )
    work_status_parser.add_argument("--store", required=True)
    work_status_parser.add_argument("--registry", required=True)
    work_status_parser.add_argument("--mission-id", required=True)
    work_status_parser.add_argument("--work-item-id")
    work_status_parser.add_argument("--output")
    work_status_parser.set_defaults(
        handler=_show_work_item_status
    )

    mission_audit_parser = subparsers.add_parser(
        "mission-audit-snapshot",
        help=(
            "Create a verified read-only operational mission "
            "snapshot"
        ),
    )
    mission_audit_parser.add_argument("--store", required=True)
    mission_audit_parser.add_argument("--registry", required=True)
    mission_audit_parser.add_argument("--mission-id", required=True)
    mission_audit_parser.add_argument("--output")
    mission_audit_parser.set_defaults(
        handler=_create_mission_audit_snapshot
    )

    work_cancel_parser = subparsers.add_parser(
        "work-cancel-authenticated",
        help=(
            "Cancel one work item and its descendants as "
            "independent Control"
        ),
    )
    work_cancel_parser.add_argument("--store", required=True)
    work_cancel_parser.add_argument("--registry", required=True)
    work_cancel_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    work_cancel_parser.add_argument("--mission-id", required=True)
    work_cancel_parser.add_argument("--work-item-id", required=True)
    work_cancel_parser.add_argument(
        "--expected-generation",
        type=int,
        required=True,
    )
    work_cancel_parser.add_argument("--previous-transition-id")
    work_cancel_parser.add_argument("--expected-lease-expires-at")
    work_cancel_parser.add_argument("--reason-code", required=True)
    work_cancel_parser.add_argument("--reason", required=True)
    work_cancel_parser.add_argument("--risk", required=True)
    work_cancel_parser.add_argument(
        "--decision-owner",
        required=True,
    )
    work_cancel_parser.add_argument("--output")
    work_cancel_parser.set_defaults(
        handler=_cancel_work_authenticated
    )

    work_cancellation_status_parser = subparsers.add_parser(
        "work-cancellation-status",
        help="Show one verified work cancellation",
    )
    work_cancellation_status_parser.add_argument(
        "--store",
        required=True,
    )
    work_cancellation_status_parser.add_argument(
        "--registry",
        required=True,
    )
    work_cancellation_status_parser.add_argument(
        "--cancellation-id",
        required=True,
    )
    work_cancellation_status_parser.add_argument("--output")
    work_cancellation_status_parser.set_defaults(
        handler=_show_work_cancellation
    )

    work_handoff_parser = subparsers.add_parser(
        "work-handoff-authenticated",
        help=(
            "Atomically hand specialist work to an assigned "
            "qualified peer"
        ),
    )
    work_handoff_parser.add_argument("--store", required=True)
    work_handoff_parser.add_argument("--registry", required=True)
    work_handoff_parser.add_argument(
        "--owner-assertion",
        required=True,
    )
    work_handoff_parser.add_argument(
        "--candidate-assertion",
        required=True,
    )
    work_handoff_parser.add_argument("--mission-id", required=True)
    work_handoff_parser.add_argument("--work-item-id", required=True)
    work_handoff_parser.add_argument(
        "--expected-generation",
        type=int,
        required=True,
    )
    work_handoff_parser.add_argument("--previous-transition-id")
    work_handoff_parser.add_argument(
        "--expected-lease-expires-at"
    )
    work_handoff_parser.add_argument("--reason-code", required=True)
    work_handoff_parser.add_argument("--reason", required=True)
    work_handoff_parser.add_argument("--output")
    work_handoff_parser.set_defaults(
        handler=_handoff_work_authenticated
    )

    work_handoff_status_parser = subparsers.add_parser(
        "work-handoff-status",
        help="Show one verified specialist work handoff",
    )
    work_handoff_status_parser.add_argument(
        "--store",
        required=True,
    )
    work_handoff_status_parser.add_argument(
        "--registry",
        required=True,
    )
    work_handoff_status_parser.add_argument(
        "--handoff-id",
        required=True,
    )
    work_handoff_status_parser.add_argument("--output")
    work_handoff_status_parser.set_defaults(
        handler=_show_work_handoff
    )

    work_recovery_request_parser = subparsers.add_parser(
        "work-recovery-request-authenticated",
        help="Request same-owner recovery after three claim attempts",
    )
    work_recovery_request_parser.add_argument(
        "--store",
        required=True,
    )
    work_recovery_request_parser.add_argument(
        "--registry",
        required=True,
    )
    work_recovery_request_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    work_recovery_request_parser.add_argument(
        "--mission-id",
        required=True,
    )
    work_recovery_request_parser.add_argument(
        "--work-item-id",
        required=True,
    )
    work_recovery_request_parser.add_argument(
        "--expected-generation",
        type=int,
        required=True,
    )
    work_recovery_request_parser.add_argument(
        "--previous-transition-id",
        required=True,
    )
    work_recovery_request_parser.add_argument(
        "--expected-lease-expires-at",
        required=True,
    )
    work_recovery_request_parser.add_argument(
        "--reason-code",
        required=True,
    )
    work_recovery_request_parser.add_argument(
        "--reason",
        required=True,
    )
    work_recovery_request_parser.add_argument(
        "--remediation",
        required=True,
    )
    work_recovery_request_parser.add_argument("--output")
    work_recovery_request_parser.set_defaults(
        handler=_request_work_recovery_authenticated
    )

    work_recovery_approve_parser = subparsers.add_parser(
        "work-recovery-approve-authenticated",
        help="Approve one recovery epoch as independent Control",
    )
    work_recovery_approve_parser.add_argument(
        "--store",
        required=True,
    )
    work_recovery_approve_parser.add_argument(
        "--registry",
        required=True,
    )
    work_recovery_approve_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    work_recovery_approve_parser.add_argument(
        "--recovery-request-id",
        required=True,
    )
    work_recovery_approve_parser.add_argument(
        "--decision-owner",
        required=True,
    )
    work_recovery_approve_parser.add_argument(
        "--authority",
        required=True,
    )
    work_recovery_approve_parser.add_argument(
        "--constraint",
        action="append",
        required=True,
    )
    work_recovery_approve_parser.add_argument("--output")
    work_recovery_approve_parser.set_defaults(
        handler=_approve_work_recovery_authenticated
    )

    work_recovery_deny_parser = subparsers.add_parser(
        "work-recovery-deny-authenticated",
        help="Deny recovery and record terminal failure",
    )
    work_recovery_deny_parser.add_argument("--store", required=True)
    work_recovery_deny_parser.add_argument(
        "--registry",
        required=True,
    )
    work_recovery_deny_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    work_recovery_deny_parser.add_argument(
        "--recovery-request-id",
        required=True,
    )
    work_recovery_deny_parser.add_argument(
        "--decision-owner",
        required=True,
    )
    work_recovery_deny_parser.add_argument(
        "--reason-code",
        required=True,
    )
    work_recovery_deny_parser.add_argument("--reason", required=True)
    work_recovery_deny_parser.add_argument("--risk", required=True)
    work_recovery_deny_parser.add_argument("--output")
    work_recovery_deny_parser.set_defaults(
        handler=_deny_work_recovery_authenticated
    )

    work_recovery_status_parser = subparsers.add_parser(
        "work-recovery-status",
        help="Show one verified recovery request and decision",
    )
    work_recovery_status_parser.add_argument("--store", required=True)
    work_recovery_status_parser.add_argument(
        "--registry",
        required=True,
    )
    work_recovery_status_parser.add_argument(
        "--recovery-request-id",
        required=True,
    )
    work_recovery_status_parser.add_argument("--output")
    work_recovery_status_parser.set_defaults(
        handler=_show_work_recovery_status
    )

    events_parser = subparsers.add_parser(
        "validate-events",
        help="Validate an append-only mission event journal",
    )
    events_parser.add_argument("--registry", required=True)
    events_parser.add_argument("--mission", required=True)
    events_parser.add_argument("--events", required=True)
    events_parser.add_argument("--output")
    events_parser.set_defaults(handler=_validate_events)

    route_parser = subparsers.add_parser(
        "route",
        help="Route a structured capability request through trusted pilot policy",
    )
    route_parser.add_argument("--registry", required=True)
    route_parser.add_argument("--capabilities", required=True)
    route_parser.add_argument("--policy", required=True)
    route_parser.add_argument("--request", required=True)
    route_parser.add_argument(
        "--mission-output",
        help="Write the resolved mission request for create-mission",
    )
    route_parser.add_argument("--output")
    route_parser.set_defaults(handler=_route)

    init_store_parser = subparsers.add_parser(
        "init-store",
        help="Initialize a durable SQLite mission store",
    )
    init_store_parser.add_argument("--store", required=True)
    init_store_parser.add_argument("--output")
    init_store_parser.set_defaults(handler=_init_store)

    trust_status_parser = subparsers.add_parser(
        "trust-status",
        help="Show pinned root and trust policy state",
    )
    trust_status_parser.add_argument("--store", required=True)
    trust_status_parser.add_argument("--output")
    trust_status_parser.set_defaults(handler=_trust_status)

    trust_pin_root_parser = subparsers.add_parser(
        "trust-pin-root",
        help="Pin one out-of-band verified Ed25519 root public key",
    )
    trust_pin_root_parser.add_argument("--store", required=True)
    trust_pin_root_parser.add_argument("--root-key-id", required=True)
    trust_pin_root_parser.add_argument("--audience", required=True)
    trust_pin_root_parser.add_argument(
        "--root-public-key",
        required=True,
        help="Canonical unpadded base64url for the raw 32-byte public key",
    )
    trust_pin_root_parser.add_argument(
        "--expected-key-hash",
        required=True,
        help="Out-of-band sha256 fingerprint of the raw public key",
    )
    trust_pin_root_parser.add_argument("--output")
    trust_pin_root_parser.set_defaults(handler=_trust_pin_root)

    trust_apply_policy_parser = subparsers.add_parser(
        "trust-apply-policy",
        help="Verify and apply a root-signed principal trust policy",
    )
    trust_apply_policy_parser.add_argument("--store", required=True)
    trust_apply_policy_parser.add_argument("--policy", required=True)
    trust_apply_policy_parser.add_argument("--output")
    trust_apply_policy_parser.set_defaults(handler=_trust_apply_policy)

    scope_accept_parser = subparsers.add_parser(
        "scope-accept",
        help="Verify and accept a signed mission scope grant",
    )
    scope_accept_parser.add_argument("--store", required=True)
    scope_accept_parser.add_argument("--registry", required=True)
    scope_accept_parser.add_argument(
        "--scope-grant",
        required=True,
    )
    scope_accept_parser.add_argument("--output")
    scope_accept_parser.set_defaults(handler=_scope_accept)

    scope_revoke_parser = subparsers.add_parser(
        "scope-revoke",
        help="Verify and accept an externally signed scope-grant revocation",
    )
    scope_revoke_parser.add_argument("--store", required=True)
    scope_revoke_parser.add_argument("--registry", required=True)
    scope_revoke_parser.add_argument(
        "--scope-grant-revocation",
        required=True,
    )
    scope_revoke_parser.add_argument("--output")
    scope_revoke_parser.set_defaults(handler=_scope_revoke)

    migrate_store_parser = subparsers.add_parser(
        "migrate-store",
        help=(
            "Migrate a verified v1 through v15 mission store to v16"
        ),
    )
    migrate_store_parser.add_argument("--store", required=True)
    migrate_store_parser.add_argument("--registry", required=True)
    migrate_store_parser.add_argument(
        "--backup-destination",
        required=True,
    )
    migrate_store_parser.add_argument("--output")
    migrate_store_parser.set_defaults(handler=_migrate_store)

    create_mission_parser = subparsers.add_parser(
        "create-mission",
        help="Store an immutable mission and assembled cell",
    )
    create_mission_parser.add_argument("--store", required=True)
    create_mission_parser.add_argument("--registry", required=True)
    create_mission_parser.add_argument("--mission", required=True)
    create_mission_parser.add_argument("--output")
    create_mission_parser.set_defaults(handler=_create_mission)

    authenticated_create_parser = subparsers.add_parser(
        "mission-create-authenticated",
        help=(
            "Create a mission, accept its signed scope grant, and "
            "consume a signed principal assertion atomically"
        ),
    )
    authenticated_create_parser.add_argument("--store", required=True)
    authenticated_create_parser.add_argument(
        "--registry",
        required=True,
    )
    authenticated_create_parser.add_argument(
        "--mission",
        required=True,
    )
    authenticated_create_parser.add_argument(
        "--scope-grant",
        required=True,
    )
    authenticated_create_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    authenticated_create_parser.add_argument("--output")
    authenticated_create_parser.set_defaults(
        handler=_create_mission_authenticated
    )

    show_mission_parser = subparsers.add_parser(
        "show-mission",
        help="Show a verified stored mission",
    )
    show_mission_parser.add_argument("--store", required=True)
    show_mission_parser.add_argument("--registry", required=True)
    show_mission_parser.add_argument("--mission-id", required=True)
    show_mission_parser.add_argument("--output")
    show_mission_parser.set_defaults(handler=_show_mission)

    list_missions_parser = subparsers.add_parser(
        "list-missions",
        help="List stored missions with verified mission contexts",
    )
    list_missions_parser.add_argument("--store", required=True)
    list_missions_parser.add_argument("--registry", required=True)
    list_missions_parser.add_argument("--limit", type=int, default=100)
    list_missions_parser.add_argument("--after")
    list_missions_parser.add_argument("--output")
    list_missions_parser.set_defaults(handler=_list_missions)

    append_events_parser = subparsers.add_parser(
        "append-events",
        help="Atomically append validated events to a stored mission",
    )
    append_events_parser.add_argument("--store", required=True)
    append_events_parser.add_argument("--registry", required=True)
    append_events_parser.add_argument("--events", required=True)
    append_events_parser.add_argument("--mission-id")
    append_events_parser.add_argument("--expected-revision", type=int)
    append_events_parser.add_argument("--output")
    append_events_parser.set_defaults(handler=_append_events)

    authenticated_append_parser = subparsers.add_parser(
        "event-append-authenticated",
        help="Append events with a signed principal assertion",
    )
    authenticated_append_parser.add_argument(
        "--store",
        required=True,
    )
    authenticated_append_parser.add_argument(
        "--registry",
        required=True,
    )
    authenticated_append_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    authenticated_append_parser.add_argument(
        "--events",
        required=True,
    )
    authenticated_append_parser.add_argument(
        "--mission-id",
        required=True,
    )
    authenticated_append_parser.add_argument(
        "--expected-revision",
        type=int,
        required=True,
    )
    authenticated_append_parser.add_argument("--output")
    authenticated_append_parser.set_defaults(
        handler=_append_events_authenticated
    )

    export_events_parser = subparsers.add_parser(
        "export-events",
        help="Export verified durable mission events",
    )
    export_events_parser.add_argument("--store", required=True)
    export_events_parser.add_argument("--registry", required=True)
    export_events_parser.add_argument("--mission-id", required=True)
    export_events_parser.add_argument("--after-sequence", type=int, default=0)
    export_events_parser.add_argument("--limit", type=int)
    export_events_parser.add_argument("--output")
    export_events_parser.set_defaults(handler=_export_events)

    verify_store_parser = subparsers.add_parser(
        "verify-store",
        help="Verify SQLite, mission context, event chains, and event replay",
    )
    verify_store_parser.add_argument("--store", required=True)
    verify_store_parser.add_argument("--registry", required=True)
    verify_store_parser.add_argument("--mission-id")
    verify_store_parser.add_argument("--output")
    verify_store_parser.set_defaults(handler=_verify_store)

    backup_store_parser = subparsers.add_parser(
        "backup-store",
        help="Create a verified online backup without overwriting files",
    )
    backup_store_parser.add_argument("--store", required=True)
    backup_store_parser.add_argument("--registry", required=True)
    backup_store_parser.add_argument("--destination", required=True)
    backup_store_parser.add_argument("--output")
    backup_store_parser.set_defaults(handler=_backup_store)

    approval_submit_parser = subparsers.add_parser(
        "approval-submit",
        help="Submit a stored proposal for simulation-only review",
    )
    approval_submit_parser.add_argument("--store", required=True)
    approval_submit_parser.add_argument("--registry", required=True)
    approval_submit_parser.add_argument("--mission-id", required=True)
    approval_submit_parser.add_argument("--proposal-id", required=True)
    approval_submit_parser.add_argument(
        "--executor-profile-id",
        required=True,
    )
    approval_submit_parser.add_argument("--review-expires-at", required=True)
    approval_submit_parser.add_argument("--idempotency-key", required=True)
    approval_submit_parser.add_argument(
        "--principal-profile-id",
        required=True,
    )
    approval_submit_parser.add_argument("--output")
    approval_submit_parser.set_defaults(handler=_approval_submit)

    authenticated_submit_parser = subparsers.add_parser(
        "approval-submit-authenticated",
        help="Submit one proposal with a signed principal assertion",
    )
    authenticated_submit_parser.add_argument("--store", required=True)
    authenticated_submit_parser.add_argument("--registry", required=True)
    authenticated_submit_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    authenticated_submit_parser.add_argument(
        "--mission-id",
        required=True,
    )
    authenticated_submit_parser.add_argument(
        "--proposal-id",
        required=True,
    )
    authenticated_submit_parser.add_argument(
        "--executor-profile-id",
        required=True,
    )
    authenticated_submit_parser.add_argument(
        "--review-expires-at",
        required=True,
    )
    authenticated_submit_parser.add_argument(
        "--idempotency-key",
        required=True,
    )
    authenticated_submit_parser.add_argument("--output")
    authenticated_submit_parser.set_defaults(
        handler=_approval_submit_authenticated
    )

    approval_list_parser = subparsers.add_parser(
        "approval-list",
        help="List mission approval records",
    )
    approval_list_parser.add_argument("--store", required=True)
    approval_list_parser.add_argument("--registry", required=True)
    approval_list_parser.add_argument("--mission-id", required=True)
    approval_list_parser.add_argument(
        "--state",
        choices=[state.value for state in ApprovalState],
    )
    approval_list_parser.add_argument("--output")
    approval_list_parser.set_defaults(handler=_approval_list)

    approval_approve_parser = subparsers.add_parser(
        "approval-approve",
        help="Approve one request for plan-only simulation",
    )
    approval_approve_parser.add_argument("--store", required=True)
    approval_approve_parser.add_argument("--registry", required=True)
    approval_approve_parser.add_argument("--approval-id", required=True)
    approval_approve_parser.add_argument("--authority", required=True)
    approval_approve_parser.add_argument(
        "--constraint",
        action="append",
        required=True,
    )
    approval_approve_parser.add_argument(
        "--authorization-expires-at",
        required=True,
    )
    approval_approve_parser.add_argument("--idempotency-key", required=True)
    approval_approve_parser.add_argument(
        "--expected-version",
        type=int,
        required=True,
    )
    approval_approve_parser.add_argument(
        "--principal-profile-id",
        required=True,
    )
    approval_approve_parser.add_argument("--output")
    approval_approve_parser.set_defaults(handler=_approval_approve)

    authenticated_approve_parser = subparsers.add_parser(
        "approval-approve-authenticated",
        help="Approve one request with a signed principal assertion",
    )
    authenticated_approve_parser.add_argument("--store", required=True)
    authenticated_approve_parser.add_argument(
        "--registry",
        required=True,
    )
    authenticated_approve_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    authenticated_approve_parser.add_argument(
        "--approval-id",
        required=True,
    )
    authenticated_approve_parser.add_argument(
        "--authority",
        required=True,
    )
    authenticated_approve_parser.add_argument(
        "--constraint",
        action="append",
        required=True,
    )
    authenticated_approve_parser.add_argument(
        "--authorization-expires-at",
        required=True,
    )
    authenticated_approve_parser.add_argument(
        "--idempotency-key",
        required=True,
    )
    authenticated_approve_parser.add_argument(
        "--expected-version",
        type=int,
        required=True,
    )
    authenticated_approve_parser.add_argument("--output")
    authenticated_approve_parser.set_defaults(
        handler=_approval_approve_authenticated
    )

    approval_deny_parser = subparsers.add_parser(
        "approval-deny",
        help="Deny one pending approval and append a blocker",
    )
    approval_deny_parser.add_argument("--store", required=True)
    approval_deny_parser.add_argument("--registry", required=True)
    approval_deny_parser.add_argument("--approval-id", required=True)
    approval_deny_parser.add_argument("--reason-code", required=True)
    approval_deny_parser.add_argument("--reason", required=True)
    approval_deny_parser.add_argument("--risk", required=True)
    approval_deny_parser.add_argument("--decision-owner", required=True)
    approval_deny_parser.add_argument("--idempotency-key", required=True)
    approval_deny_parser.add_argument(
        "--expected-version",
        type=int,
        required=True,
    )
    approval_deny_parser.add_argument(
        "--principal-profile-id",
        required=True,
    )
    approval_deny_parser.add_argument("--output")
    approval_deny_parser.set_defaults(handler=_approval_deny)

    authenticated_deny_parser = subparsers.add_parser(
        "approval-deny-authenticated",
        help="Deny one request with a signed principal assertion",
    )
    authenticated_deny_parser.add_argument("--store", required=True)
    authenticated_deny_parser.add_argument(
        "--registry",
        required=True,
    )
    authenticated_deny_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    authenticated_deny_parser.add_argument(
        "--approval-id",
        required=True,
    )
    authenticated_deny_parser.add_argument(
        "--reason-code",
        required=True,
    )
    authenticated_deny_parser.add_argument("--reason", required=True)
    authenticated_deny_parser.add_argument("--risk", required=True)
    authenticated_deny_parser.add_argument(
        "--decision-owner",
        required=True,
    )
    authenticated_deny_parser.add_argument(
        "--idempotency-key",
        required=True,
    )
    authenticated_deny_parser.add_argument(
        "--expected-version",
        type=int,
        required=True,
    )
    authenticated_deny_parser.add_argument("--output")
    authenticated_deny_parser.set_defaults(
        handler=_approval_deny_authenticated
    )

    approval_revoke_parser = subparsers.add_parser(
        "approval-revoke",
        help="Revoke one approved, unconsumed simulation authorization",
    )
    approval_revoke_parser.add_argument("--store", required=True)
    approval_revoke_parser.add_argument("--registry", required=True)
    approval_revoke_parser.add_argument("--approval-id", required=True)
    approval_revoke_parser.add_argument("--reason-code", required=True)
    approval_revoke_parser.add_argument("--reason", required=True)
    approval_revoke_parser.add_argument("--risk", required=True)
    approval_revoke_parser.add_argument(
        "--decision-owner",
        required=True,
    )
    approval_revoke_parser.add_argument(
        "--idempotency-key",
        required=True,
    )
    approval_revoke_parser.add_argument(
        "--expected-version",
        type=int,
        required=True,
    )
    approval_revoke_parser.add_argument(
        "--principal-profile-id",
        required=True,
    )
    approval_revoke_parser.add_argument("--output")
    approval_revoke_parser.set_defaults(handler=_approval_revoke)

    authenticated_revoke_parser = subparsers.add_parser(
        "approval-revoke-authenticated",
        help=(
            "Revoke one approved authorization with a signed principal "
            "assertion"
        ),
    )
    authenticated_revoke_parser.add_argument("--store", required=True)
    authenticated_revoke_parser.add_argument(
        "--registry",
        required=True,
    )
    authenticated_revoke_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    authenticated_revoke_parser.add_argument(
        "--approval-id",
        required=True,
    )
    authenticated_revoke_parser.add_argument(
        "--reason-code",
        required=True,
    )
    authenticated_revoke_parser.add_argument(
        "--reason",
        required=True,
    )
    authenticated_revoke_parser.add_argument("--risk", required=True)
    authenticated_revoke_parser.add_argument(
        "--decision-owner",
        required=True,
    )
    authenticated_revoke_parser.add_argument(
        "--idempotency-key",
        required=True,
    )
    authenticated_revoke_parser.add_argument(
        "--expected-version",
        type=int,
        required=True,
    )
    authenticated_revoke_parser.add_argument("--output")
    authenticated_revoke_parser.set_defaults(
        handler=_approval_revoke_authenticated
    )

    mission_status_parser = subparsers.add_parser(
        "mission-status",
        help="Show verified terminal mission control state",
    )
    mission_status_parser.add_argument("--store", required=True)
    mission_status_parser.add_argument("--registry", required=True)
    mission_status_parser.add_argument("--mission-id", required=True)
    mission_status_parser.add_argument("--output")
    mission_status_parser.set_defaults(handler=_mission_status)

    mission_stop_parser = subparsers.add_parser(
        "mission-stop",
        help="Trusted-local stop before trust policy enrollment",
    )
    mission_stop_parser.add_argument("--store", required=True)
    mission_stop_parser.add_argument("--registry", required=True)
    mission_stop_parser.add_argument("--mission-id", required=True)
    mission_stop_parser.add_argument(
        "--reason-code",
        required=True,
        choices=[reason.value for reason in MissionStopReason],
    )
    mission_stop_parser.add_argument("--reason", required=True)
    mission_stop_parser.add_argument("--risk", required=True)
    mission_stop_parser.add_argument(
        "--decision-owner",
        required=True,
    )
    mission_stop_parser.add_argument(
        "--idempotency-key",
        required=True,
    )
    mission_stop_parser.add_argument(
        "--expected-version",
        type=int,
        required=True,
    )
    mission_stop_parser.add_argument(
        "--principal-profile-id",
        required=True,
    )
    mission_stop_parser.add_argument("--output")
    mission_stop_parser.set_defaults(handler=_mission_stop)

    authenticated_stop_parser = subparsers.add_parser(
        "mission-stop-authenticated",
        help="Stop a mission with a signed principal assertion",
    )
    authenticated_stop_parser.add_argument("--store", required=True)
    authenticated_stop_parser.add_argument(
        "--registry",
        required=True,
    )
    authenticated_stop_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    authenticated_stop_parser.add_argument(
        "--mission-id",
        required=True,
    )
    authenticated_stop_parser.add_argument(
        "--reason-code",
        required=True,
        choices=[reason.value for reason in MissionStopReason],
    )
    authenticated_stop_parser.add_argument(
        "--reason",
        required=True,
    )
    authenticated_stop_parser.add_argument("--risk", required=True)
    authenticated_stop_parser.add_argument(
        "--decision-owner",
        required=True,
    )
    authenticated_stop_parser.add_argument(
        "--idempotency-key",
        required=True,
    )
    authenticated_stop_parser.add_argument(
        "--expected-version",
        type=int,
        required=True,
    )
    authenticated_stop_parser.add_argument("--output")
    authenticated_stop_parser.set_defaults(
        handler=_mission_stop_authenticated
    )

    simulate_parser = subparsers.add_parser(
        "simulate",
        help="Consume an approval through the non-executing policy simulator",
    )
    simulate_parser.add_argument("--store", required=True)
    simulate_parser.add_argument("--registry", required=True)
    simulate_parser.add_argument("--approval-id", required=True)
    simulate_parser.add_argument("--idempotency-key", required=True)
    simulate_parser.add_argument("--principal-profile-id", required=True)
    simulate_parser.add_argument("--output")
    simulate_parser.set_defaults(handler=_simulate)

    authenticated_simulate_parser = subparsers.add_parser(
        "simulate-authenticated",
        help="Consume an approval with a signed principal assertion",
    )
    authenticated_simulate_parser.add_argument("--store", required=True)
    authenticated_simulate_parser.add_argument(
        "--registry",
        required=True,
    )
    authenticated_simulate_parser.add_argument(
        "--principal-assertion",
        required=True,
    )
    authenticated_simulate_parser.add_argument(
        "--approval-id",
        required=True,
    )
    authenticated_simulate_parser.add_argument(
        "--idempotency-key",
        required=True,
    )
    authenticated_simulate_parser.add_argument("--output")
    authenticated_simulate_parser.set_defaults(
        handler=_simulate_authenticated
    )

    content_parser = subparsers.add_parser(
        "check-content",
        help="Check repository text content",
    )
    content_parser.add_argument("--root", default=".")
    content_parser.add_argument("--output")
    content_parser.set_defaults(handler=_check_content)
    offline_review_parser = subparsers.add_parser(
        "offline-review-run",
        help="Build one effect-free bundle from same-tenant offline review inputs",
    )
    remediation_case_parser = subparsers.add_parser(
        "remediation-case-review",
        help="Join exact local remediation sources without declaring a current fix",
    )
    remediation_case_verify_parser = subparsers.add_parser(
        "remediation-case-review-verify",
        help="Replay a saved advisory remediation case from its complete local sources",
    )
    for selected in (remediation_case_parser, remediation_case_verify_parser):
        selected.add_argument("--input", required=True)
    remediation_case_parser.set_defaults(handler=_run_remediation_case_review)
    remediation_case_verify_parser.add_argument("--review", required=True)
    remediation_case_verify_parser.set_defaults(handler=_verify_remediation_case_review)
    mcp_preflight_parser = subparsers.add_parser(
        "mcp-catalog-preflight",
        help="Lint a proposed MCP tool catalog without starting a server",
    )
    mcp_preflight_parser.add_argument("--manifest", required=True)
    mcp_preflight_parser.set_defaults(handler=_run_mcp_catalog_preflight)
    mcp_preflight_verify_parser = subparsers.add_parser(
        "mcp-catalog-preflight-verify",
        help="Reproduce an MCP catalog preflight from its exact manifest",
    )
    mcp_preflight_verify_parser.add_argument("--manifest", required=True)
    mcp_preflight_verify_parser.add_argument("--preflight", required=True)
    mcp_preflight_verify_parser.set_defaults(handler=_verify_mcp_catalog_preflight)
    mcp_schema_parser = subparsers.add_parser(
        "mcp-schema-byte-preflight",
        help="Bind declared MCP schema digests to exact supplied JSON bytes",
    )
    mcp_schema_verify_parser = subparsers.add_parser(
        "mcp-schema-byte-preflight-verify",
        help="Reproduce an MCP schema-byte preflight from exact sources",
    )
    for selected in (mcp_schema_parser, mcp_schema_verify_parser):
        for name in ("manifest", "preflight", "schemas"):
            selected.add_argument(f"--{name}", required=True)
    mcp_schema_parser.set_defaults(handler=_run_mcp_schema_byte_preflight)
    mcp_schema_verify_parser.add_argument("--result", required=True)
    mcp_schema_verify_parser.set_defaults(handler=_verify_mcp_schema_byte_preflight)
    mcp_semantic_parser = subparsers.add_parser(
        "mcp-schema-semantic-preflight",
        help="Check supplied MCP schemas against bounded JSON Schema 2020-12 semantics",
    )
    mcp_semantic_verify_parser = subparsers.add_parser(
        "mcp-schema-semantic-preflight-verify",
        help="Reproduce a bounded MCP schema semantic preflight",
    )
    for selected in (mcp_semantic_parser, mcp_semantic_verify_parser):
        for name in ("manifest", "preflight", "schemas", "byte-result"):
            selected.add_argument(f"--{name}", required=True)
    mcp_semantic_parser.set_defaults(handler=_run_mcp_schema_semantic_preflight)
    mcp_semantic_verify_parser.add_argument("--result", required=True)
    mcp_semantic_verify_parser.set_defaults(
        handler=_verify_mcp_schema_semantic_preflight
    )
    mcp_header_parser = subparsers.add_parser(
        "mcp-header-annotation-preflight",
        help="Check static MCP tool header annotations without HTTP requests",
    )
    mcp_header_verify_parser = subparsers.add_parser(
        "mcp-header-annotation-preflight-verify",
        help="Reproduce the MCP header annotation preflight",
    )
    for selected in (mcp_header_parser, mcp_header_verify_parser):
        for name in (
            "manifest", "preflight", "schemas", "byte-result", "semantic-result",
        ):
            selected.add_argument(f"--{name}", required=True)
    mcp_header_parser.set_defaults(handler=_run_mcp_header_annotation_preflight)
    mcp_header_verify_parser.add_argument("--result", required=True)
    mcp_header_verify_parser.set_defaults(
        handler=_verify_mcp_header_annotation_preflight
    )
    mcp_bindings_parser = subparsers.add_parser(
        "mcp-api-read-bindings",
        help="Bind declared MCP read tools to the closed API read vocabulary",
    )
    mcp_bindings_verify_parser = subparsers.add_parser(
        "mcp-api-read-bindings-verify",
        help="Reproduce a static MCP-to-API read binding plan",
    )
    for selected in (mcp_bindings_parser, mcp_bindings_verify_parser):
        for name in ("manifest", "preflight", "bindings"):
            selected.add_argument(f"--{name}", required=True)
    mcp_bindings_parser.set_defaults(handler=_run_mcp_api_read_bindings)
    mcp_bindings_verify_parser.add_argument("--plan", required=True)
    mcp_bindings_verify_parser.set_defaults(handler=_verify_mcp_api_read_bindings)
    agent_trace_parser = subparsers.add_parser(
        "agent-trace-review",
        help="Review redacted agent trace metadata without model or tool calls",
    )
    agent_trace_parser.add_argument("--trace", required=True)
    agent_trace_parser.set_defaults(handler=_run_agent_trace_review)
    agent_trace_verify_parser = subparsers.add_parser(
        "agent-trace-review-verify",
        help="Reproduce an agent trace review from its exact redacted trace",
    )
    agent_trace_verify_parser.add_argument("--trace", required=True)
    agent_trace_verify_parser.add_argument("--review", required=True)
    agent_trace_verify_parser.set_defaults(handler=_verify_agent_trace_review)
    agent_trace_regression_parser = subparsers.add_parser(
        "agent-trace-regression",
        help="Compare two reproduced same-policy redacted agent trace reviews",
    )
    agent_trace_regression_verify_parser = subparsers.add_parser(
        "agent-trace-regression-verify",
        help="Reproduce a redacted agent trace comparison from exact sources",
    )
    for selected in (agent_trace_regression_parser, agent_trace_regression_verify_parser):
        for name in ("prior-trace", "prior-review", "current-trace", "current-review"):
            selected.add_argument(f"--{name}", required=True)
    agent_trace_regression_parser.set_defaults(handler=_run_agent_trace_regression)
    agent_trace_regression_verify_parser.add_argument("--comparison", required=True)
    agent_trace_regression_verify_parser.set_defaults(handler=_verify_agent_trace_regression)
    offline_review_parser.add_argument("--input", required=True)
    offline_review_parser.set_defaults(handler=_run_offline_review)
    offline_review_verify_parser = subparsers.add_parser(
        "offline-review-verify",
        help="Reproduce and compare an offline review bundle from its input",
    )
    offline_review_verify_parser.add_argument("--input", required=True)
    offline_review_verify_parser.add_argument("--bundle", required=True)
    offline_review_verify_parser.set_defaults(handler=_verify_offline_review)
    traffic_inventory_verify_parser = subparsers.add_parser(
        "traffic-api-inventory-verify",
        help="Replay a stored traffic API inventory from sanitized source files",
    )
    traffic_inventory_verify_parser.add_argument("--inventory", required=True)
    traffic_inventory_verify_parser.add_argument("--observations", required=True)
    traffic_inventory_verify_parser.add_argument("--contract-bundle")
    traffic_inventory_verify_parser.set_defaults(handler=_verify_traffic_api_inventory)
    offline_handoff_parser = subparsers.add_parser(
        "offline-review-handoff",
        help="Prepare an independent-review handoff from a reproduced bundle",
    )
    offline_handoff_parser.add_argument("--input", required=True)
    offline_handoff_parser.add_argument("--bundle", required=True)
    offline_handoff_parser.set_defaults(handler=_run_offline_review_handoff)
    offline_handoff_verify_parser = subparsers.add_parser(
        "offline-review-handoff-verify",
        help="Reproduce and compare an offline commander review handoff",
    )
    offline_handoff_verify_parser.add_argument("--input", required=True)
    offline_handoff_verify_parser.add_argument("--bundle", required=True)
    offline_handoff_verify_parser.add_argument("--handoff", required=True)
    offline_handoff_verify_parser.set_defaults(handler=_verify_offline_review_handoff)
    offline_transition_parser = subparsers.add_parser(
        "offline-review-transition",
        help="Compare two reproduced same-scope offline review snapshots",
    )
    offline_transition_verify_parser = subparsers.add_parser(
        "offline-review-transition-verify",
        help="Reproduce and verify an offline review transition",
    )
    for selected in (offline_transition_parser, offline_transition_verify_parser):
        for name in (
            "prior-input", "prior-bundle", "prior-handoff",
            "current-input", "current-bundle", "current-handoff",
        ):
            selected.add_argument(f"--{name}", required=True)
    offline_transition_parser.set_defaults(handler=_run_offline_review_transition)
    offline_transition_verify_parser.add_argument("--transition", required=True)
    offline_transition_verify_parser.set_defaults(
        handler=_verify_offline_review_transition,
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        _validate_write_path_collisions(args)
        args.handler(args)
    except SunderkeyError as exc:
        raise SystemExit(f"Validation error: {exc}") from exc


if __name__ == "__main__":
    main()
