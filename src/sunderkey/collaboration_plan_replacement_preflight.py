"""Fail-closed preflight contracts for activated collaboration plan replacement."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .collaboration import CollaborationPlan, WorkItem, WorkItemKind
from .collaboration_mission_policy import (
    CollaborationMissionReconfigurationPolicy,
    collaboration_mission_reconfiguration_selection_sha256,
)
from .errors import CollaborationPlanError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
PREFLIGHT_DOMAIN = "sunderkey.collaboration-plan-replacement-preflight.v1"
SELECTION_DOMAIN = "sunderkey.collaboration-plan-replacement-selection.v1"
AUTHORITY_INTENT_DOMAIN = "sunderkey.collaboration-plan-replacement-authority-intent.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
TIMESTAMP_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
AUTHENTICATION_ID_PATTERN = re.compile(r"MPA-[0-9A-F]{32}")
PREFLIGHT_ID_PATTERN = re.compile(r"PRF-[0-9A-F]{32}")
REQUIREMENT_ID_PATTERN = re.compile(r"PAR-[0-9A-F]{32}")

SOURCE_STATES = frozenset({"completed", "not_completed"})
DISPOSITIONS = frozenset({"preserve_completed_result", "restart_in_replacement"})
MAPPING_INPUT_FIELDS = frozenset(
    {
        "source_work_item_id",
        "replacement_work_item_id",
        "source_state",
        "disposition",
        "completed_result_sha256",
        "cross_command_evidence",
    }
)
CROSS_COMMAND_EVIDENCE_FIELDS = frozenset(
    {
        "capability_revalidation_sha256",
        "capability_catalog_sha256",
        "proposed_owner_qualification_sha256",
        "source_command_review_sha256",
        "destination_command_review_sha256",
    }
)
SOURCE_STATE_FIELDS = frozenset(
    {
        "mission_revision",
        "active_plan_id",
        "active_plan_sha256",
        "ownership_snapshot_sha256",
        "work_snapshot_sha256",
        "cancellation_snapshot_sha256",
        "execution_session_snapshot_sha256",
        "terminal_custody_snapshot_sha256",
        "observed_at",
    }
)
POLICY_COMMIT_FIELDS = frozenset(
    {
        "policy_id",
        "policy_sha256",
        "policy_selection_sha256",
        "authentication_id",
        "authentication_sha256",
        "committed_at",
        "mission_owner_assertion_id",
        "mission_owner_assertion_sha256",
        "mission_owner_ledger_entry_sha256",
        "independent_control_assertion_id",
        "independent_control_assertion_sha256",
        "independent_control_ledger_entry_sha256",
        "commit_status",
    }
)
AUTHORITY_REQUIREMENT_FIELDS = frozenset(
    {
        "requirement_id",
        "role",
        "authority_id",
        "authority_kind",
        "operation",
        "work_item_id",
        "operation_intent_sha256",
    }
)


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _optional_sha256(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _sha256(value, label)


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise CollaborationPlanError(f"{label} is invalid") from exc
    if parsed.microsecond:
        raise CollaborationPlanError(f"{label} must use whole seconds")
    return value


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def _positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise CollaborationPlanError(f"{label} must be a positive integer")
    return value


def _plan(value: Any, label: str) -> CollaborationPlan:
    if not isinstance(value, CollaborationPlan):
        raise CollaborationPlanError(f"{label} must be a CollaborationPlan")
    return CollaborationPlan.from_dict(value.to_dict())


def _owner_class(item: WorkItem) -> str:
    classes = {
        WorkItemKind.READINESS: "mission_coordination",
        WorkItemKind.SPECIALIST_ANALYSIS: "specialist",
        WorkItemKind.DOMAIN_SYNTHESIS: "domain_command",
        WorkItemKind.GROUP_INTEGRATION: "mission_coordination",
        WorkItemKind.CROSS_SURFACE_INTEGRATION: "mission_coordination",
        WorkItemKind.CONTROL_REVIEW: "independent_control",
        WorkItemKind.EVIDENCE_REVIEW: "independent_assurance",
        WorkItemKind.ASSURANCE_REVIEW: "independent_assurance",
    }
    return classes[item.kind]


def _readiness_owner(plan: CollaborationPlan) -> str:
    readiness_items = tuple(item for item in plan.work_items if item.kind is WorkItemKind.READINESS)
    if len(readiness_items) != 1:
        raise CollaborationPlanError("Collaboration plan must contain one readiness item")
    return readiness_items[0].owner_profile_id


def _objective_sha256(item: WorkItem) -> str:
    return _canonical_sha256(
        {
            "domain": "sunderkey.collaboration-work-objective.v1",
            "kind": item.kind.value,
            "role_mission": item.role_mission,
            "deliverable": item.deliverable,
        }
    )


def _plan_reference(plan: CollaborationPlan) -> dict[str, str]:
    return {"plan_id": plan.plan_id, "plan_sha256": plan.content_sha256}


def _source_mission_revision(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise CollaborationPlanError(
            "source_state.mission_revision must be a native nonnegative integer"
        )
    return value


def _source_state(raw: Any, prior: CollaborationPlan) -> dict[str, Any]:
    value = _mapping(raw, "source_state")
    _exact_fields(value, set(SOURCE_STATE_FIELDS), "source_state")
    active_plan_id = _identifier(value.get("active_plan_id"), "source_state.active_plan_id")
    active_plan_sha256 = _sha256(value.get("active_plan_sha256"), "source_state.active_plan_sha256")
    if active_plan_id != prior.plan_id or active_plan_sha256 != prior.content_sha256:
        raise CollaborationPlanError("Source state does not bind the active prior plan")
    return {
        "mission_revision": _source_mission_revision(value.get("mission_revision")),
        "active_plan_id": active_plan_id,
        "active_plan_sha256": active_plan_sha256,
        "ownership_snapshot_sha256": _sha256(
            value.get("ownership_snapshot_sha256"),
            "source_state.ownership_snapshot_sha256",
        ),
        "work_snapshot_sha256": _sha256(
            value.get("work_snapshot_sha256"), "source_state.work_snapshot_sha256"
        ),
        "cancellation_snapshot_sha256": _sha256(
            value.get("cancellation_snapshot_sha256"),
            "source_state.cancellation_snapshot_sha256",
        ),
        "execution_session_snapshot_sha256": _sha256(
            value.get("execution_session_snapshot_sha256"),
            "source_state.execution_session_snapshot_sha256",
        ),
        "terminal_custody_snapshot_sha256": _sha256(
            value.get("terminal_custody_snapshot_sha256"),
            "source_state.terminal_custody_snapshot_sha256",
        ),
        "observed_at": _timestamp(value.get("observed_at"), "source_state.observed_at"),
    }


def _policy_commit_binding(
    raw: Any,
    policy: CollaborationMissionReconfigurationPolicy,
    prior: CollaborationPlan,
) -> dict[str, str]:
    value = _mapping(raw, "mission_policy_commit")
    _exact_fields(value, set(POLICY_COMMIT_FIELDS), "mission_policy_commit")
    document = policy.to_dict()
    expected = {
        "policy_id": policy.policy_id,
        "policy_sha256": policy.policy_sha256,
        "policy_selection_sha256": (collaboration_mission_reconfiguration_selection_sha256(policy)),
    }
    if any(value.get(field) != expected[field] for field in expected):
        raise CollaborationPlanError("Mission policy commit binding is stale")
    if document["mission_id"] != prior.mission_id:
        raise CollaborationPlanError("Mission policy binds a different mission")
    if (
        document["collaboration_plan_id"] != prior.plan_id
        or document["collaboration_plan_sha256"] != prior.content_sha256
    ):
        raise CollaborationPlanError("Mission policy binds a different active plan")
    if document["transition_activation"]["activated_plan_replacement"] is not True:
        raise CollaborationPlanError("Mission policy does not activate plan replacement")
    authentication_id = value.get("authentication_id")
    if (
        not isinstance(authentication_id, str)
        or AUTHENTICATION_ID_PATTERN.fullmatch(authentication_id) is None
    ):
        raise CollaborationPlanError("mission_policy_commit.authentication_id is invalid")
    approvals = document["approval_bindings"]
    authority_bindings = {
        "mission_owner_assertion_id": _identifier(
            value.get("mission_owner_assertion_id"),
            "mission_policy_commit.mission_owner_assertion_id",
        ),
        "mission_owner_assertion_sha256": _sha256(
            value.get("mission_owner_assertion_sha256"),
            "mission_policy_commit.mission_owner_assertion_sha256",
        ),
        "mission_owner_ledger_entry_sha256": _sha256(
            value.get("mission_owner_ledger_entry_sha256"),
            "mission_policy_commit.mission_owner_ledger_entry_sha256",
        ),
        "independent_control_assertion_id": _identifier(
            value.get("independent_control_assertion_id"),
            "mission_policy_commit.independent_control_assertion_id",
        ),
        "independent_control_assertion_sha256": _sha256(
            value.get("independent_control_assertion_sha256"),
            "mission_policy_commit.independent_control_assertion_sha256",
        ),
        "independent_control_ledger_entry_sha256": _sha256(
            value.get("independent_control_ledger_entry_sha256"),
            "mission_policy_commit.independent_control_ledger_entry_sha256",
        ),
    }
    if (
        authority_bindings["mission_owner_assertion_id"]
        != approvals["mission_owner"]["assertion_id"]
        or authority_bindings["mission_owner_assertion_sha256"]
        != approvals["mission_owner"]["assertion_sha256"]
        or authority_bindings["independent_control_assertion_id"]
        != approvals["independent_control"]["assertion_id"]
        or authority_bindings["independent_control_assertion_sha256"]
        != approvals["independent_control"]["assertion_sha256"]
    ):
        raise CollaborationPlanError("Mission policy authority provenance is stale")
    if value.get("commit_status") != "committed_inactive":
        raise CollaborationPlanError("Mission policy commit status is invalid")
    return {
        **expected,
        "authentication_id": authentication_id,
        "authentication_sha256": _sha256(
            value.get("authentication_sha256"),
            "mission_policy_commit.authentication_sha256",
        ),
        "committed_at": _timestamp(value.get("committed_at"), "mission_policy_commit.committed_at"),
        **authority_bindings,
        "commit_status": "committed_inactive",
    }


def _cross_command_evidence(raw: Any, label: str) -> dict[str, str] | None:
    if raw is None:
        return None
    value = _mapping(raw, label)
    _exact_fields(value, set(CROSS_COMMAND_EVIDENCE_FIELDS), label)
    return {
        field: _sha256(value.get(field), f"{label}.{field}")
        for field in sorted(CROSS_COMMAND_EVIDENCE_FIELDS)
    }


def _mapping_requests(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise CollaborationPlanError("mapping_inputs must be a list")
    result: list[dict[str, Any]] = []
    source_ids: set[str] = set()
    target_ids: set[str] = set()
    for index, item_raw in enumerate(raw):
        label = f"mapping_inputs[{index}]"
        item = _mapping(item_raw, label)
        _exact_fields(item, set(MAPPING_INPUT_FIELDS), label)
        source_id = _identifier(item.get("source_work_item_id"), f"{label}.source_work_item_id")
        target_id = _identifier(
            item.get("replacement_work_item_id"), f"{label}.replacement_work_item_id"
        )
        if source_id in source_ids or target_id in target_ids:
            raise CollaborationPlanError("Plan replacement mappings must be one to one")
        source_ids.add(source_id)
        target_ids.add(target_id)
        result.append(dict(item))
    return result


def _authority_requirement(
    *,
    role: str,
    authority_id: str,
    authority_kind: str,
    operation: str,
    work_item_id: str | None,
    selection_sha256: str,
) -> dict[str, Any]:
    body = {
        "role": role,
        "authority_id": authority_id,
        "authority_kind": authority_kind,
        "operation": operation,
        "work_item_id": work_item_id,
        "selection_sha256": selection_sha256,
    }
    operation_intent_sha256 = _canonical_sha256(
        {"domain": AUTHORITY_INTENT_DOMAIN, "authority_intent": body}
    )
    digest = _canonical_sha256(
        {
            "domain": "sunderkey.collaboration-plan-replacement-authority-requirement.v1",
            "requirement": {**body, "operation_intent_sha256": operation_intent_sha256},
        }
    )
    return {
        "requirement_id": "PAR-" + digest.removeprefix("sha256:")[:32].upper(),
        "role": role,
        "authority_id": authority_id,
        "authority_kind": authority_kind,
        "operation": operation,
        "work_item_id": work_item_id,
        "operation_intent_sha256": operation_intent_sha256,
    }


def _deduplicate_requirements(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_identity: dict[tuple[str, str, str, str | None], dict[str, Any]] = {}
    for item in items:
        key = (
            item["role"],
            item["authority_id"],
            item["operation"],
            item["work_item_id"],
        )
        by_identity[key] = item
    return sorted(by_identity.values(), key=lambda item: item["requirement_id"])


@dataclass(frozen=True)
class CollaborationPlanReplacementPreflight:
    """Immutable plan replacement selection awaiting authority authentication."""

    preflight_id: str
    preflight_sha256: str
    selection_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationPlanReplacementPreflight:
        value = _mapping(raw, "collaboration plan replacement preflight")
        fields = {
            "schema_version",
            "preflight_id",
            "preflight_sha256",
            "selection_sha256",
            "mission_id",
            "prior_plan",
            "replacement_plan",
            "mission_policy_commit",
            "source_state",
            "item_mappings",
            "cancellation_actions",
            "new_item_actions",
            "authority_requirements",
            "maximum_mapping_items",
            "atomic_commit_required",
            "history_policy",
            "authentication_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration plan replacement preflight")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Plan replacement preflight schema is invalid")
        preflight_id = value.get("preflight_id")
        if (
            not isinstance(preflight_id, str)
            or PREFLIGHT_ID_PATTERN.fullmatch(preflight_id) is None
        ):
            raise CollaborationPlanError("Plan replacement preflight identity is invalid")
        preflight_sha256 = _sha256(value.get("preflight_sha256"), "preflight_sha256")
        selection_sha256 = _sha256(value.get("selection_sha256"), "selection_sha256")
        _identifier(value.get("mission_id"), "mission_id")
        for label in ("prior_plan", "replacement_plan"):
            reference = _mapping(value.get(label), label)
            _exact_fields(reference, {"plan_id", "plan_sha256"}, label)
            _identifier(reference.get("plan_id"), f"{label}.plan_id")
            _sha256(reference.get("plan_sha256"), f"{label}.plan_sha256")
        if value["prior_plan"] == value["replacement_plan"]:
            raise CollaborationPlanError("Replacement plan must differ from prior plan")
        policy = _mapping(value.get("mission_policy_commit"), "mission_policy_commit")
        _exact_fields(policy, set(POLICY_COMMIT_FIELDS), "mission_policy_commit")
        state = _mapping(value.get("source_state"), "source_state")
        _exact_fields(state, set(SOURCE_STATE_FIELDS), "source_state")
        _source_mission_revision(state.get("mission_revision"))
        for collection in (
            "item_mappings",
            "cancellation_actions",
            "new_item_actions",
            "authority_requirements",
        ):
            if not isinstance(value.get(collection), list):
                raise CollaborationPlanError(f"{collection} must be a list")
        requirement_ids: set[str] = set()
        for index, raw_requirement in enumerate(value["authority_requirements"]):
            label = f"authority_requirements[{index}]"
            requirement = _mapping(raw_requirement, label)
            _exact_fields(requirement, set(AUTHORITY_REQUIREMENT_FIELDS), label)
            requirement_id = requirement.get("requirement_id")
            if (
                not isinstance(requirement_id, str)
                or REQUIREMENT_ID_PATTERN.fullmatch(requirement_id) is None
                or requirement_id in requirement_ids
            ):
                raise CollaborationPlanError("Authority requirement identity is invalid")
            requirement_ids.add(requirement_id)
            _sha256(requirement.get("operation_intent_sha256"), f"{label}.operation_intent_sha256")
        maximum = _positive_integer(value.get("maximum_mapping_items"), "maximum_mapping_items")
        item_count = sum(
            len(value[name])
            for name in ("item_mappings", "cancellation_actions", "new_item_actions")
        )
        if item_count > maximum:
            raise CollaborationPlanError("Plan replacement mapping limit is exceeded")
        if value.get("atomic_commit_required") is not True:
            raise CollaborationPlanError("Plan replacement must require atomic commit")
        if value.get("history_policy") != "append_only_no_rewrite":
            raise CollaborationPlanError("Plan replacement history policy is invalid")
        if value.get("authentication_status") != "authority_assertions_required":
            raise CollaborationPlanError("Plan replacement authentication status is invalid")
        if value.get("runtime_effect") != "none":
            raise CollaborationPlanError("Plan replacement runtime effect is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"preflight_id", "preflight_sha256"}
        }
        digest = _canonical_sha256({"domain": PREFLIGHT_DOMAIN, "preflight": body})
        expected_id = "PRF-" + digest.removeprefix("sha256:")[:32].upper()
        if preflight_sha256 != digest or preflight_id != expected_id:
            raise CollaborationPlanError("Plan replacement preflight hash is invalid")
        return cls(
            preflight_id=preflight_id,
            preflight_sha256=preflight_sha256,
            selection_sha256=selection_sha256,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Plan replacement preflight is invalid")
        return value


def build_collaboration_plan_replacement_preflight(
    *,
    prior_plan: CollaborationPlan,
    replacement_plan: CollaborationPlan,
    mission_policy: CollaborationMissionReconfigurationPolicy,
    mission_policy_commit: dict[str, str],
    source_state: dict[str, Any],
    mapping_inputs: list[dict[str, Any]],
    independent_control_profile_id: str | None = None,
    independent_assurance_profile_id: str | None = None,
    second_control_profile_id: str | None = None,
) -> CollaborationPlanReplacementPreflight:
    """Build an inactive preflight from exact plans, policy, and state snapshots."""

    prior = _plan(prior_plan, "prior_plan")
    replacement = _plan(replacement_plan, "replacement_plan")
    if prior.mission_id != replacement.mission_id:
        raise CollaborationPlanError("Replacement plan mission changed")
    if prior.plan_id == replacement.plan_id or prior.content_sha256 == replacement.content_sha256:
        raise CollaborationPlanError("Replacement plan must have a new identity and digest")
    policy = CollaborationMissionReconfigurationPolicy.from_dict(mission_policy.to_dict())
    policy_document = policy.to_dict()
    policy_binding = _policy_commit_binding(mission_policy_commit, policy, prior)
    state_binding = _source_state(source_state, prior)
    if _timestamp_value(state_binding["observed_at"]) < _timestamp_value(
        policy_binding["committed_at"]
    ):
        raise CollaborationPlanError("Source state predates the committed mission policy")
    if not (
        _timestamp_value(policy_document["effective_at"])
        <= _timestamp_value(state_binding["observed_at"])
        < _timestamp_value(policy_document["expires_at"])
    ):
        raise CollaborationPlanError("Plan replacement preflight is outside the policy window")
    maximum = policy_document["selected_parameters"]["maximum_plan_replacement_items"]
    requests = _mapping_requests(mapping_inputs)
    prior_items = {item.work_item_id: item for item in prior.work_items}
    replacement_items = {item.work_item_id: item for item in replacement.work_items}
    mapped_source_ids = {item["source_work_item_id"] for item in requests}
    mapped_target_ids = {item["replacement_work_item_id"] for item in requests}
    if not mapped_source_ids <= set(prior_items):
        raise CollaborationPlanError("Plan replacement maps an unknown source work item")
    if not mapped_target_ids <= set(replacement_items):
        raise CollaborationPlanError("Plan replacement maps an unknown replacement work item")
    source_to_replacement = {
        item["source_work_item_id"]: item["replacement_work_item_id"] for item in requests
    }
    mappings: list[dict[str, Any]] = []
    needs_assurance = False
    needs_second_control = False
    for request in sorted(requests, key=lambda item: item["source_work_item_id"]):
        source = prior_items[request["source_work_item_id"]]
        target = replacement_items[request["replacement_work_item_id"]]
        source_state_value = request.get("source_state")
        disposition = request.get("disposition")
        if source_state_value not in SOURCE_STATES or disposition not in DISPOSITIONS:
            raise CollaborationPlanError("Plan replacement source state or disposition is invalid")
        completed_result = _optional_sha256(
            request.get("completed_result_sha256"), "completed_result_sha256"
        )
        if (source_state_value == "completed") != (completed_result is not None):
            raise CollaborationPlanError("Completed source state requires an exact result digest")
        source_objective = _objective_sha256(source)
        target_objective = _objective_sha256(target)
        source_class = _owner_class(source)
        target_class = _owner_class(target)
        translated_dependencies = {
            source_to_replacement[item]
            for item in source.dependency_ids
            if item in source_to_replacement
        }
        same_dependency_meaning = len(translated_dependencies) == len(
            source.dependency_ids
        ) and translated_dependencies == set(target.dependency_ids)
        preservation_eligible = all(
            (
                source_objective == target_objective,
                source_class == target_class,
                source.required_evidence_level == target.required_evidence_level,
                same_dependency_meaning,
            )
        )
        if disposition == "preserve_completed_result" and (
            source_state_value != "completed" or not preservation_eligible
        ):
            raise CollaborationPlanError("Completed result is not eligible for preservation")
        cross_command = (source.command_id, source.group_id) != (
            target.command_id,
            target.group_id,
        )
        if (
            cross_command
            and policy_document["transition_activation"]["cross_command_transfer"] is not True
        ):
            raise CollaborationPlanError(
                "Mission policy does not activate cross-command replacement"
            )
        cross_evidence = _cross_command_evidence(
            request.get("cross_command_evidence"), "cross_command_evidence"
        )
        if cross_command and cross_evidence is None:
            raise CollaborationPlanError("Cross-command mapping requires capability revalidation")
        if not cross_command and cross_evidence is not None:
            raise CollaborationPlanError("Same-command mapping cannot claim cross-command evidence")
        if cross_command and (source.command_id is None or target.command_id is None):
            raise CollaborationPlanError(
                "Cross-command mapping requires concrete source and destination commands"
            )
        if (
            source.kind is WorkItemKind.ASSURANCE_REVIEW
            or target.kind is WorkItemKind.ASSURANCE_REVIEW
        ):
            needs_assurance = True
        control_changed = (
            source.kind is WorkItemKind.CONTROL_REVIEW or target.kind is WorkItemKind.CONTROL_REVIEW
        ) and (source.owner_profile_id != target.owner_profile_id or source.kind is not target.kind)
        needs_second_control = needs_second_control or control_changed
        mappings.append(
            {
                "source_work_item_id": source.work_item_id,
                "replacement_work_item_id": target.work_item_id,
                "source_state": source_state_value,
                "disposition": disposition,
                "completed_result_sha256": completed_result,
                "source_objective_sha256": source_objective,
                "replacement_objective_sha256": target_objective,
                "source_owner_class": source_class,
                "replacement_owner_class": target_class,
                "source_required_evidence_level": source.required_evidence_level.value,
                "replacement_required_evidence_level": target.required_evidence_level.value,
                "same_dependency_meaning": same_dependency_meaning,
                "preservation_eligible": preservation_eligible,
                "cross_command": cross_command,
                "cross_command_evidence": cross_evidence,
                "current_owner_id": source.owner_profile_id,
                "proposed_owner_id": target.owner_profile_id,
            }
        )
    cancelled_ids = sorted(set(prior_items) - mapped_source_ids)
    new_ids = sorted(set(replacement_items) - mapped_target_ids)
    if len(requests) + len(cancelled_ids) + len(new_ids) > maximum:
        raise CollaborationPlanError("Plan replacement mapping limit is exceeded")
    cancellations = []
    for source_id in cancelled_ids:
        source = prior_items[source_id]
        needs_assurance = needs_assurance or source.kind is WorkItemKind.ASSURANCE_REVIEW
        needs_second_control = needs_second_control or source.kind is WorkItemKind.CONTROL_REVIEW
        cancellations.append(
            {
                "source_work_item_id": source_id,
                "current_owner_id": source.owner_profile_id,
                "disposition": "cancel_without_history_rewrite",
                "terminal_custody_required": True,
            }
        )
    new_actions = []
    for target_id in new_ids:
        target = replacement_items[target_id]
        needs_assurance = needs_assurance or target.kind is WorkItemKind.ASSURANCE_REVIEW
        needs_second_control = needs_second_control or target.kind is WorkItemKind.CONTROL_REVIEW
        new_actions.append(
            {
                "replacement_work_item_id": target_id,
                "proposed_owner_id": target.owner_profile_id,
                "disposition": "start_new_after_atomic_commit",
            }
        )
    assurance_profile = (
        None
        if independent_assurance_profile_id is None
        else _identifier(independent_assurance_profile_id, "independent_assurance_profile_id")
    )
    second_control = (
        None
        if second_control_profile_id is None
        else _identifier(second_control_profile_id, "second_control_profile_id")
    )
    if needs_assurance and assurance_profile is None:
        raise CollaborationPlanError("Plan replacement requires independent Assurance")
    if needs_second_control and second_control is None:
        raise CollaborationPlanError("Plan replacement requires a second Control authority")
    approvals = policy_document["approval_bindings"]
    mission_owner_id = approvals["mission_owner"]["profile_id"]
    policy_control_id = approvals["independent_control"]["profile_id"]
    control_id = (
        policy_control_id
        if independent_control_profile_id is None
        else _identifier(independent_control_profile_id, "independent_control_profile_id")
    )
    if mission_owner_id != _readiness_owner(prior):
        raise CollaborationPlanError(
            "Mission policy owner does not match the active plan readiness owner"
        )
    if mission_owner_id == control_id:
        raise CollaborationPlanError("Mission owner and Control must use distinct profiles")
    affected_owner_ids = {
        item.owner_profile_id for item in (*prior.work_items, *replacement.work_items)
    }
    if control_id in affected_owner_ids:
        raise CollaborationPlanError(
            "Independent Control must not own work affected by the replacement"
        )
    if assurance_profile is not None and assurance_profile in (
        {mission_owner_id, control_id} | affected_owner_ids
    ):
        raise CollaborationPlanError("Independent Assurance must use a distinct profile")
    if second_control is not None and second_control in (
        {mission_owner_id, control_id, assurance_profile} | affected_owner_ids
    ):
        raise CollaborationPlanError("Second Control must use a distinct profile")
    selection = {
        "mission_id": prior.mission_id,
        "prior_plan": _plan_reference(prior),
        "replacement_plan": _plan_reference(replacement),
        "mission_policy_commit": policy_binding,
        "source_state": state_binding,
        "item_mappings": mappings,
        "cancellation_actions": cancellations,
        "new_item_actions": new_actions,
        "independent_assurance_profile_id": assurance_profile,
        "second_control_profile_id": second_control,
        "maximum_mapping_items": maximum,
    }
    if control_id != policy_control_id:
        selection["independent_control_profile_id"] = control_id
    selection_sha256 = _canonical_sha256({"domain": SELECTION_DOMAIN, "selection": selection})
    requirements = [
        _authority_requirement(
            role="mission_owner",
            authority_id=mission_owner_id,
            authority_kind="principal_profile",
            operation="sunderkey.collaboration.plan-replacement.owner-authorize.v1",
            work_item_id=None,
            selection_sha256=selection_sha256,
        ),
        _authority_requirement(
            role="independent_control",
            authority_id=control_id,
            authority_kind="principal_profile",
            operation="sunderkey.collaboration.plan-replacement.control-approve.v1",
            work_item_id=None,
            selection_sha256=selection_sha256,
        ),
    ]
    for item in mappings:
        requirements.extend(
            (
                _authority_requirement(
                    role="current_owner",
                    authority_id=item["current_owner_id"],
                    authority_kind="principal_profile",
                    operation="sunderkey.collaboration.plan-replacement.current-owner-authorize.v1",
                    work_item_id=item["source_work_item_id"],
                    selection_sha256=selection_sha256,
                ),
                _authority_requirement(
                    role="proposed_owner",
                    authority_id=item["proposed_owner_id"],
                    authority_kind="principal_profile",
                    operation="sunderkey.collaboration.plan-replacement.proposed-owner-accept.v1",
                    work_item_id=item["replacement_work_item_id"],
                    selection_sha256=selection_sha256,
                ),
            )
        )
        if item["cross_command"]:
            source = prior_items[item["source_work_item_id"]]
            target = replacement_items[item["replacement_work_item_id"]]
            requirements.extend(
                (
                    _authority_requirement(
                        role="source_technical_command",
                        authority_id=str(source.command_id),
                        authority_kind="command",
                        operation="sunderkey.collaboration.plan-replacement.source-command-review.v1",
                        work_item_id=source.work_item_id,
                        selection_sha256=selection_sha256,
                    ),
                    _authority_requirement(
                        role="destination_technical_command",
                        authority_id=str(target.command_id),
                        authority_kind="command",
                        operation="sunderkey.collaboration.plan-replacement.destination-command-review.v1",
                        work_item_id=target.work_item_id,
                        selection_sha256=selection_sha256,
                    ),
                )
            )
    for item in cancellations:
        requirements.append(
            _authority_requirement(
                role="current_owner",
                authority_id=item["current_owner_id"],
                authority_kind="principal_profile",
                operation="sunderkey.collaboration.plan-replacement.current-owner-cancel.v1",
                work_item_id=item["source_work_item_id"],
                selection_sha256=selection_sha256,
            )
        )
    for item in new_actions:
        requirements.append(
            _authority_requirement(
                role="proposed_owner",
                authority_id=item["proposed_owner_id"],
                authority_kind="principal_profile",
                operation="sunderkey.collaboration.plan-replacement.proposed-owner-accept.v1",
                work_item_id=item["replacement_work_item_id"],
                selection_sha256=selection_sha256,
            )
        )
    if assurance_profile is not None:
        requirements.append(
            _authority_requirement(
                role="independent_assurance",
                authority_id=assurance_profile,
                authority_kind="principal_profile",
                operation="sunderkey.collaboration.plan-replacement.assurance-approve.v1",
                work_item_id=None,
                selection_sha256=selection_sha256,
            )
        )
    if second_control is not None:
        requirements.append(
            _authority_requirement(
                role="second_control",
                authority_id=second_control,
                authority_kind="principal_profile",
                operation="sunderkey.collaboration.plan-replacement.second-control-approve.v1",
                work_item_id=None,
                selection_sha256=selection_sha256,
            )
        )
    body = {
        "schema_version": SCHEMA_VERSION,
        "selection_sha256": selection_sha256,
        "mission_id": prior.mission_id,
        "prior_plan": _plan_reference(prior),
        "replacement_plan": _plan_reference(replacement),
        "mission_policy_commit": policy_binding,
        "source_state": state_binding,
        "item_mappings": mappings,
        "cancellation_actions": cancellations,
        "new_item_actions": new_actions,
        "authority_requirements": _deduplicate_requirements(requirements),
        "maximum_mapping_items": maximum,
        "atomic_commit_required": True,
        "history_policy": "append_only_no_rewrite",
        "authentication_status": "authority_assertions_required",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": PREFLIGHT_DOMAIN, "preflight": body})
    return CollaborationPlanReplacementPreflight.from_dict(
        {
            **body,
            "preflight_id": "PRF-" + digest.removeprefix("sha256:")[:32].upper(),
            "preflight_sha256": digest,
        }
    )


def verify_collaboration_plan_replacement_preflight(
    preflight: CollaborationPlanReplacementPreflight,
    *,
    prior_plan: CollaborationPlan,
    replacement_plan: CollaborationPlan,
    mission_policy: CollaborationMissionReconfigurationPolicy,
) -> CollaborationPlanReplacementPreflight:
    """Rebuild and compare every semantic and evidence binding."""

    parsed = CollaborationPlanReplacementPreflight.from_dict(preflight.to_dict())
    document = parsed.to_dict()
    mapping_inputs = [
        {field: item.get(field) for field in MAPPING_INPUT_FIELDS}
        for item in document["item_mappings"]
    ]
    assurance = next(
        (
            item["authority_id"]
            for item in document["authority_requirements"]
            if item["role"] == "independent_assurance"
        ),
        None,
    )
    second_control = next(
        (
            item["authority_id"]
            for item in document["authority_requirements"]
            if item["role"] == "second_control"
        ),
        None,
    )
    controls = [
        item["authority_id"]
        for item in document["authority_requirements"]
        if item["role"] == "independent_control"
    ]
    if len(controls) != 1:
        raise CollaborationPlanError("Plan replacement requires exactly one independent Control")
    expected = build_collaboration_plan_replacement_preflight(
        prior_plan=prior_plan,
        replacement_plan=replacement_plan,
        mission_policy=mission_policy,
        mission_policy_commit=document["mission_policy_commit"],
        source_state=document["source_state"],
        mapping_inputs=mapping_inputs,
        independent_control_profile_id=controls[0],
        independent_assurance_profile_id=assurance,
        second_control_profile_id=second_control,
    )
    if expected.to_dict() != document:
        raise CollaborationPlanError("Plan replacement semantic verification failed")
    return parsed


def load_collaboration_plan_replacement_preflight(
    path: str | Path,
) -> CollaborationPlanReplacementPreflight:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(
            f"Could not load plan replacement preflight: {resolved}"
        ) from exc
    return CollaborationPlanReplacementPreflight.from_dict(raw)


__all__ = [
    "AUTHORITY_INTENT_DOMAIN",
    "CollaborationPlanReplacementPreflight",
    "PREFLIGHT_DOMAIN",
    "SELECTION_DOMAIN",
    "build_collaboration_plan_replacement_preflight",
    "load_collaboration_plan_replacement_preflight",
    "verify_collaboration_plan_replacement_preflight",
]
