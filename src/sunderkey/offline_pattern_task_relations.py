"""Bind caller-declared pattern hypotheses to separately replayed task sources."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import offline_framework_declaration_core as core
from . import offline_specialist_task as task
from .offline_archive_member_paths import COMPONENT_ID as ARCHIVE_COMPONENT
from .offline_configuration_defaults import COMPONENT_ID as CONFIGURATION_COMPONENT
from .offline_confused_deputy_boundary import COMPONENT_ID as DEPUTY_COMPONENT
from .offline_cross_channel_session import COMPONENT_ID as SESSION_COMPONENT
from .offline_cross_surface_authorization import COMPONENT_ID as AUTHORIZATION_COMPONENT
from .offline_dependency_fail_closed import COMPONENT_ID as DEPENDENCY_COMPONENT
from .offline_dns_scope_timeline import COMPONENT_ID as DNS_COMPONENT
from .offline_integrity_poisoning import COMPONENT_ID as INTEGRITY_COMPONENT
from .offline_interpreter_input_boundary import COMPONENT_ID as INTERPRETER_COMPONENT
from .offline_json_key_policy_differential import COMPONENT_ID as JSON_COMPONENT
from .offline_observable_discrepancy import COMPONENT_ID as OBSERVABLE_COMPONENT
from .offline_pickle_opcode_inventory import COMPONENT_ID as PICKLE_COMPONENT
from .offline_query_input_boundary import COMPONENT_ID as QUERY_COMPONENT
from .offline_request_origin_trust import COMPONENT_ID as ORIGIN_COMPONENT
from .offline_resource_expansion_budget import COMPONENT_ID as BUDGET_COMPONENT
from .offline_toctou_state_schedule import COMPONENT_ID as SCHEDULE_COMPONENT

COMPONENT_ID = "supplied_pattern_task_relations"
SEMANTICS_PROFILE = "supplied-pattern-task-relation-v1"
DOMAIN = "sunderkey.offline-pattern-task-relations.v1"
MAX_PLAN_BYTES = 32_768
MAX_REPORT_BYTES = 131_072
MAX_PREMISES = 16
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SUPPORTED = {
    PICKLE_COMPONENT: {
        "profile_id": "AOE-GE-D23-S03",
        "collection": "source_review",
        "selector": "source_id",
        "expected": {
            "candidate_dynamic_behavior_opcodes",
            "no_tracked_dynamic_behavior_opcodes",
        },
        "unresolved": set(),
    },
    JSON_COMPONENT: {
        "profile_id": "AOE-GE-D23-S04",
        "collection": "field_interpretations",
        "selector": "field_name",
        "expected": {
            "candidate_first_last_difference",
            "duplicate_same_endpoint_value",
            "single_occurrence",
        },
        "unresolved": set(),
    },
    ARCHIVE_COMPONENT: {
        "profile_id": "AOE-GE-D23-S05",
        "collection": "findings",
        "selector": "entry_id",
        "expected": {
            "declared_drive_prefix",
            "declared_absolute_member",
            "declared_parent_escape",
            "lexically_contained",
            "declared_destination_collision_candidate",
        },
        "unresolved": {
            "unknown_empty_destination",
            "unknown_symlink_target",
            "unknown_name_transform",
        },
    },
    DNS_COMPONENT: {
        "profile_id": "AOE-GE-D23-S06",
        "collection": "transitions",
        "selector": ("from_snapshot_id", "to_snapshot_id"),
        "expected": {
            "candidate_global_to_internal_shift",
            "no_declared_global_to_internal_shift",
        },
        "unresolved": {"unknown_mixed_answer_shift"},
    },
    AUTHORIZATION_COMPONENT: {
        "profile_id": "AOE-GE-D23-S07",
        "collection": "comparisons",
        "selector": ("principal_ref", "action_ref", "resource_ref"),
        "expected": {
            "candidate_declared_decision_difference",
            "declared_decision_alignment",
        },
        "unresolved": {"unresolved_identity_mapping", "unresolved_decision"},
    },
    SESSION_COMPONENT: {
        "profile_id": "AOE-GE-D23-S08",
        "selector": "event_id",
        "expected": {
            "candidate_declared_cross_channel_conflict",
            "declared_reject_consistent",
            "no_declared_cross_channel_negative_invariant",
        },
        "unresolved": {
            "unresolved_declaration_or_capture",
            "unresolved_session_or_outcome",
            "unresolved_revocation_effect",
        },
    },
    ORIGIN_COMPONENT: {
        "profile_id": "AOE-GE-D23-S09",
        "selector": "observation_id",
        "expected": {
            "candidate_declared_trust_boundary_conflict",
            "declared_reject_consistent",
            "no_declared_negative_invariant",
        },
        "unresolved": {"unresolved_declaration_or_capture", "unresolved_outcome"},
    },
    SCHEDULE_COMPONENT: {
        "profile_id": "AOE-GE-D23-S10",
        "selector": "event_id",
        "expected": {
            "candidate_declared_stale_check_conflict",
            "declared_reject_consistent",
            "no_declared_negative_invariant",
        },
        "unresolved": {
            "unresolved_declaration_or_capture",
            "unresolved_check_version_mismatch",
            "unresolved_outcome",
        },
    },
    BUDGET_COMPONENT: {
        "profile_id": "AOE-GE-D23-S11",
        "selector": "operation_id",
        "expected": {
            "candidate_declared_resource_budget_conflict",
            "declared_reject_consistent",
            "no_declared_negative_invariant",
        },
        "unresolved": {"unresolved_declaration_or_capture", "unresolved_outcome"},
    },
    DEPENDENCY_COMPONENT: {
        "profile_id": "AOE-GE-D23-S12",
        "selector": "observation_id",
        "expected": {
            "candidate_declared_fail_open_conflict",
            "declared_deny_consistent",
            "no_declared_negative_invariant",
        },
        "unresolved": {
            "unresolved_declaration_or_capture",
            "unresolved_decision_or_dependency",
            "unresolved_fallback_outcome_mismatch",
        },
    },
    CONFIGURATION_COMPONENT: {
        "profile_id": "AOE-GE-D23-S13",
        "selector": "setting_id",
        "expected": {
            "candidate_declared_insecure_default",
            "candidate_declared_insecure_override",
            "declared_required_value_consistent",
        },
        "unresolved": {
            "unresolved_declaration_or_capture",
            "unresolved_effective_value",
            "unresolved_effective_value_mismatch",
        },
    },
    DEPUTY_COMPONENT: {
        "profile_id": "AOE-GE-D23-S14",
        "selector": "operation_id",
        "expected": {
            "candidate_declared_deputy_boundary_conflict",
            "declared_requester_boundary_consistent",
            "no_declared_deputy_boundary_conflict",
        },
        "unresolved": {
            "unresolved_declaration_or_capture",
            "unresolved_authority_or_result",
        },
    },
    INTEGRITY_COMPONENT: {
        "profile_id": "AOE-GE-D23-S15",
        "selector": "artifact_id",
        "expected": {
            "candidate_declared_untrusted_content_consumption",
            "candidate_declared_integrity_policy_conflict",
            "declared_integrity_rejection_consistent",
            "no_declared_integrity_conflict",
        },
        "unresolved": {
            "unresolved_declaration_or_capture",
            "unresolved_origin_or_consumption",
        },
    },
    QUERY_COMPONENT: {
        "profile_id": "AOE-GE-D23-S01",
        "selector": "query_id",
        "expected": {
            "candidate_declared_query_input_boundary_conflict",
            "declared_unexecuted_query_construction_conflict",
            "no_declared_unbound_query_input",
        },
        "unresolved": {
            "unresolved_declaration_or_capture",
            "unresolved_input_trust_or_incorporation",
        },
    },
    INTERPRETER_COMPONENT: {
        "profile_id": "AOE-GE-D23-S02",
        "selector": "sink_id",
        "expected": {
            "candidate_declared_interpreter_input_boundary_conflict",
            "declared_uninvoked_interpreter_construction_conflict",
            "no_declared_interpreted_untrusted_input",
        },
        "unresolved": {
            "unresolved_declaration_or_capture",
            "unresolved_input_trust_or_incorporation",
        },
    },
    OBSERVABLE_COMPONENT: {
        "profile_id": "AOE-GE-D23-S16",
        "selector": "comparison_id",
        "expected": {
            "candidate_declared_sensitive_field_exposure",
            "declared_observable_discrepancy_without_sensitive_marker",
            "declared_restricted_fields_consistent",
        },
        "unresolved": {"unresolved_declaration_or_capture"},
    },
}
_EFFECTS = dict.fromkeys(
    ("authority", "credential", "execution", "filesystem", "network",
     "publication", "qualification", "target"),
    "none",
)

PatternTaskRelationsError = core.FrameworkDeclarationError


def _reject_constant(_value: str) -> None:
    raise PatternTaskRelationsError("Nonfinite JSON number is not permitted")


def _parse_document(content: bytes, *, maximum: int, label: str) -> Any:
    if type(content) is not bytes or len(content) > maximum:
        raise PatternTaskRelationsError(f"{label} must be bounded native bytes")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise PatternTaskRelationsError(
                    f"Duplicate {label.lower()} member is not permitted"
                )
            result[key] = value
        return result

    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PatternTaskRelationsError(f"{label} is not bounded UTF-8 JSON") from exc
    return value


def parse_supplied_pattern_task_relations_plan(content: bytes) -> dict:
    """Parse one bounded local plan without composing or trusting task sources."""
    return _plan(_parse_document(content, maximum=MAX_PLAN_BYTES, label="Plan"))


def _sha(value: Any) -> str:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise PatternTaskRelationsError("Source model digest is invalid")
    return value


def _plan(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_PLAN_BYTES)
    plan = json.loads(core.canonical(value))
    item = core.exact(
        plan,
        {"schema_version", "semantics_profile", "plan_id", "scope_binding", "premises"},
        "plan",
    )
    if type(item["schema_version"]) is not int or item["schema_version"] != 1:
        raise PatternTaskRelationsError("Schema version is invalid")
    if item["semantics_profile"] != SEMANTICS_PROFILE:
        raise PatternTaskRelationsError("Semantics profile is invalid")
    core.identifier(item["plan_id"], "plan ID")
    binding = core.exact(
        item["scope_binding"], {"scope_id", "basis", "job_ids"}, "scope binding"
    )
    core.identifier(binding["scope_id"], "scope ID")
    if binding["basis"] != "caller_declared_unverified":
        raise PatternTaskRelationsError("Scope basis must remain unverified")
    job_ids = core.bounded_list(binding["job_ids"], MAX_PREMISES, "bound jobs")
    if len(job_ids) < 2:
        raise PatternTaskRelationsError("At least two distinct jobs must be bound")
    for job_id in job_ids:
        core.identifier(job_id, "job ID")
    if len(set(job_ids)) != len(job_ids):
        raise PatternTaskRelationsError("Bound job identifier is repeated")
    premises = core.bounded_list(item["premises"], MAX_PREMISES, "premises")
    if len(premises) < 2:
        raise PatternTaskRelationsError("At least two premises are required")
    premise_ids: set[str] = set()
    selections: set[tuple[str, str]] = set()
    premise_jobs: set[str] = set()
    for raw in premises:
        premise = core.exact(
            raw,
            {"premise_id", "job_id", "component_id", "source_model_sha256",
             "projection_id", "expected_disposition"},
            "premise",
        )
        premise_id = core.identifier(premise["premise_id"], "premise ID")
        job_id = core.identifier(premise["job_id"], "job ID")
        projection_id = core.identifier(premise["projection_id"], "projection ID")
        if premise_id in premise_ids or (job_id, projection_id) in selections:
            raise PatternTaskRelationsError("Premise or selected projection is repeated")
        premise_ids.add(premise_id)
        selections.add((job_id, projection_id))
        premise_jobs.add(job_id)
        component_id = premise["component_id"]
        if type(component_id) is not str or component_id not in _SUPPORTED:
            raise PatternTaskRelationsError("Unsupported fixed component")
        _sha(premise["source_model_sha256"])
        if (
            type(premise["expected_disposition"]) is not str
            or premise["expected_disposition"] not in _SUPPORTED[component_id]["expected"]
        ):
            raise PatternTaskRelationsError("Expected disposition is unsupported")
    if premise_jobs != set(job_ids):
        raise PatternTaskRelationsError("Scope jobs must exactly match premise jobs")
    if len({premise["component_id"] for premise in premises}) < 2:
        raise PatternTaskRelationsError("At least two distinct specialists are required")
    return plan


def _derive(
    model: Any,
    *,
    task_report: Any,
    task_model: Any,
    catalog: Any,
    repository_root: str | Path,
) -> dict:
    plan = _plan(model)
    try:
        verified = task.verify_offline_specialist_task(
            task_report, model=task_model, catalog=catalog, repository_root=repository_root
        ).to_dict()
    except task.OfflineSpecialistTaskError as exc:
        raise PatternTaskRelationsError("Original task or current sources do not replay") from exc
    original = verified["model"]
    requests = {row["job_id"]: row["request"] for row in original["jobs"]}
    results = {row["job_id"]: row["result"] for row in verified["jobs"]}
    projections = []
    for premise in sorted(plan["premises"], key=lambda row: row["premise_id"]):
        job_id = premise["job_id"]
        if job_id not in requests or job_id not in results:
            raise PatternTaskRelationsError("Bound job is absent from original task")
        request = requests[job_id]
        result = results[job_id]
        component_id = premise["component_id"]
        expected_profile = _SUPPORTED[component_id]["profile_id"]
        if (
            request.get("profile_id") != expected_profile
            or request.get("component_id") != component_id
            or result["component"]["profile_id"] != expected_profile
            or result["component"]["component_id"] != component_id
        ):
            raise PatternTaskRelationsError("Premise does not select its original component")
        source_model = request["payload"]["model"]
        source_sha256 = core.digest(core.canonical(source_model).encode("ascii"))
        if source_sha256 != premise["source_model_sha256"]:
            raise PatternTaskRelationsError("Premise original source digest differs")
        analysis = result["analysis"]
        if core.canonical(analysis["source_model"]) != core.canonical(source_model):
            raise PatternTaskRelationsError("Leaf source differs from original task")
        supported = _SUPPORTED[component_id]
        selector = supported["selector"]
        collection = supported.get("collection", "projections")
        if collection == "source_review":
            source_rows = [
                {
                    "source_id": source_model["source_id"],
                    "disposition": analysis["review_disposition"],
                }
            ]
        else:
            source_rows = analysis[collection]
        if type(selector) is tuple:
            selections = [
                (
                    row,
                    core.digest(
                        core.canonical({key: row[key] for key in selector}).encode("ascii")
                    ),
                )
                for row in source_rows
            ]
        else:
            selections = [(row, row.get(selector)) for row in source_rows]
        matches = [
            row for row, selection in selections
            if selection == premise["projection_id"]
        ]
        if len(matches) != 1:
            raise PatternTaskRelationsError("Projection selection is missing or ambiguous")
        actual = matches[0]["disposition"]
        if actual in supported["unresolved"]:
            status = "unresolved"
        elif actual in supported["expected"]:
            status = (
                "matches_declared_expectation"
                if actual == premise["expected_disposition"]
                else "contradicts_declared_expectation"
            )
        else:
            raise PatternTaskRelationsError("Leaf disposition is unsupported")
        projections.append(
            {"premise_id": premise["premise_id"], "job_id": job_id,
             "component_id": component_id, "projection_id": premise["projection_id"],
             "source_model_sha256": source_sha256,
             "expected_disposition": premise["expected_disposition"],
             "actual_disposition": actual, "status": status,
             "leaf_analysis_id": analysis["analysis_id"],
             "leaf_analysis_sha256": analysis["analysis_sha256"]}
        )
    statuses = {row["status"] for row in projections}
    if "contradicts_declared_expectation" in statuses:
        hypothesis_status = "contradicts_declared_expectation"
    elif "unresolved" in statuses:
        hypothesis_status = "unresolved"
    else:
        hypothesis_status = "matches_declared_expectation"
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "source_model": plan,
        "task_binding": {
            key: verified[key]
            for key in ("task_id", "task_result_id", "task_result_sha256",
                        "model_sha256", "catalog_id", "catalog_sha256")
        },
        "premise_count": len(projections),
        "premises": projections,
        "hypothesis_status": hypothesis_status,
        "scope_equivalence_proven": False,
        "source_authenticated": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Premises are caller-declared and leaf analyses are separately replayed.",
            "Matching dispositions do not establish a shared target or exploit chain.",
            "The report is unsigned and does not authorize action or qualification.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PTR-")
    report = {**body, "analysis_id": report_id, "analysis_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return json.loads(core.canonical(report))


@dataclass(frozen=True, slots=True, init=False)
class PatternTaskRelations:
    """Result requiring separate original task and current-source replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise PatternTaskRelationsError("Use analysis or source-replaying verification")

    @classmethod
    def _owned(cls, document: dict) -> PatternTaskRelations:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_pattern_task_relations(
    model: Any, *, task_report: Any, task_model: Any, catalog: Any,
    repository_root: str | Path,
) -> PatternTaskRelations:
    """Project explicit hypotheses over one separately replayed offline task."""
    return PatternTaskRelations._owned(
        _derive(
            model, task_report=task_report, task_model=task_model,
            catalog=catalog, repository_root=repository_root,
        )
    )


def verify_supplied_pattern_task_relations(
    report: Any, *, model: Any, task_report: Any, task_model: Any, catalog: Any,
    repository_root: str | Path,
) -> PatternTaskRelations:
    if type(report) is not PatternTaskRelations:
        raise PatternTaskRelationsError("Exact native relation wrapper required")
    expected = _derive(
        model, task_report=task_report, task_model=task_model,
        catalog=catalog, repository_root=repository_root,
    )
    if report.to_json() != core.canonical(expected):
        raise PatternTaskRelationsError("Relations differ from separate original replay")
    return PatternTaskRelations._owned(expected)


def verify_supplied_pattern_task_relations_bytes(
    report_bytes: bytes, *, model: Any, task_report: Any, task_model: Any,
    catalog: Any, repository_root: str | Path,
) -> PatternTaskRelations:
    """Rebuild an untrusted exported report from separate original/current sources."""
    report = _parse_document(report_bytes, maximum=MAX_REPORT_BYTES, label="Report")
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    expected = _derive(
        model, task_report=task_report, task_model=task_model,
        catalog=catalog, repository_root=repository_root,
    )
    if core.canonical(report) != core.canonical(expected):
        raise PatternTaskRelationsError("Report differs from separate original replay")
    return PatternTaskRelations._owned(expected)
