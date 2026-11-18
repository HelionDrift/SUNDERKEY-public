"""Durable collaboration workspace for source-bound expert runtime products."""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from .errors import StoreConflictError, StoreError, StoreIntegrityError
from .expert_review import MAX_RECORD_BYTES as MAX_EXPERT_REVIEW_RECORD_BYTES
from .expert_review import (
    ExpertReviewClosureCertificate,
    ExpertReviewClosureRevocation,
    ExpertReviewReconciliationReport,
    ExpertReviewRecordSet,
    ExpertReviewSnapshot,
    ExpertWorkspaceClosureApplication,
    ReconciliationStatus,
    build_expert_review_snapshot,
    build_expert_workspace_closure_application,
    derive_reviewer_role,
    parse_expert_review_closure_certificate,
    parse_expert_review_closure_revocation,
    parse_expert_review_snapshot,
    parse_expert_workspace_closure_application,
    verify_expert_review_record_set,
)
from .expert_runtime import (
    CATALOG_DOMAIN,
    MAX_EXECUTION_ENVELOPE_BYTES,
    MAX_WORK_PRODUCT_BYTES,
    RuntimePackCatalog,
    WorkProduct,
    parse_execution_envelope,
    parse_work_product,
)
from .qualification import _canonical_json, _canonical_sha256
from .registry import ExpertRegistry
from .validation import DuplicateJsonKeyError, loads_json_without_duplicate_keys

APPLICATION_ID = 0x53574B57
SCHEMA_VERSION = 3
WORKSPACE_DOMAIN = "sunderkey.expert-collaboration-workspace.v1"
EVENT_DOMAIN = "sunderkey.expert-workspace-event.v1"
LEASE_DOMAIN = "sunderkey.expert-workspace-lease.v1"
ACCEPTANCE_DOMAIN = "sunderkey.expert-workspace-acceptance.v1"
MAX_WORKSPACES = 4096
MAX_ASSIGNMENTS = 512
MAX_DEPENDENCIES = 4096
MAX_REVIEWERS_PER_WORK = 64
MAX_DEFINITION_BYTES = 2_097_152
MAX_LEASE_SECONDS = 86_400
MAX_ATTEMPTS_PER_WORK = 8

_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_WORKSPACE_ID_PATTERN = re.compile(r"EWS-[0-9A-F]{32}")
_LEASE_ID_PATTERN = re.compile(r"EWL-[0-9A-F]{32}")
_EVENT_ID_PATTERN = re.compile(r"EWE-[0-9A-F]{32}")
_PROFILE_ID_PATTERN = re.compile(r"AOE-(?:G[A-E]-D[0-9]{2}-(?:S[0-9]{2}|CMD)|HQ-[0-9]{2})")
_HQ_PROFILE_ID_PATTERN = re.compile(r"AOE-HQ-(?:0[1-9]|[12][0-9]|3[0-5])")

_EXPECTED_SCHEMA_OBJECTS_V1 = frozenset(
    {
        ("index", "expert_workspaces_tenant_mission_plan"),
        ("table", "expert_workspaces"),
        ("table", "workspace_assignments"),
        ("table", "workspace_dependencies"),
        ("table", "workspace_disagreements"),
        ("table", "workspace_events"),
        ("table", "workspace_leases"),
        ("table", "workspace_product_lineage"),
        ("table", "workspace_products"),
        ("table", "workspace_review_requirements"),
        ("table", "workspace_store_identity"),
        ("trigger", "expert_workspaces_core_immutable"),
        ("trigger", "expert_workspaces_no_delete"),
        ("trigger", "expert_workspaces_revision_guard"),
        ("trigger", "expert_workspaces_status_guard"),
        ("trigger", "workspace_assignments_core_immutable"),
        ("trigger", "workspace_assignments_no_delete"),
        ("trigger", "workspace_dependencies_no_delete"),
        ("trigger", "workspace_dependencies_no_update"),
        ("trigger", "workspace_disagreements_no_delete"),
        ("trigger", "workspace_disagreements_no_update"),
        ("trigger", "workspace_events_no_delete"),
        ("trigger", "workspace_events_no_update"),
        ("trigger", "workspace_leases_core_immutable"),
        ("trigger", "workspace_leases_no_delete"),
        ("trigger", "workspace_leases_status_guard"),
        ("trigger", "workspace_lineage_no_delete"),
        ("trigger", "workspace_lineage_no_update"),
        ("trigger", "workspace_products_no_delete"),
        ("trigger", "workspace_products_no_update"),
        ("trigger", "workspace_reviews_no_delete"),
        ("trigger", "workspace_reviews_no_update"),
    }
)

_EXPECTED_SCHEMA_OBJECTS_V2 = _EXPECTED_SCHEMA_OBJECTS_V1 | frozenset(
    {
        ("table", "workspace_review_closure_imports"),
        ("table", "workspace_review_closure_revocations"),
        ("trigger", "workspace_closure_imports_no_delete"),
        ("trigger", "workspace_closure_imports_no_update"),
        ("trigger", "workspace_closure_revocations_no_delete"),
        ("trigger", "workspace_closure_revocations_no_update"),
    }
)
_EXPECTED_SCHEMA_OBJECTS = _EXPECTED_SCHEMA_OBJECTS_V2 | frozenset(
    {
        ("index", "workspace_store_identity_store_id"),
        ("trigger", "workspace_store_identity_immutable"),
        ("trigger", "workspace_store_identity_no_delete"),
    }
)


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if isinstance(value, str):
        if not value or len(value.encode("utf-8")) > MAX_DEFINITION_BYTES:
            raise StoreError(f"{label} exceeds the JSON byte ceiling")
        try:
            value = loads_json_without_duplicate_keys(value)
        except (json.JSONDecodeError, DuplicateJsonKeyError) as exc:
            raise StoreError(f"{label} JSON is invalid") from exc
    if not isinstance(value, Mapping):
        raise StoreError(f"{label} must be an object")
    return dict(value)


def _exact(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise StoreError(f"{label} fields are invalid")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _ID_PATTERN.fullmatch(value) is None:
        raise StoreError(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise StoreError(f"{label} is invalid")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise StoreError(f"{label} is invalid")
    return value


def _stored_integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise StoreIntegrityError(f"Stored {label} is invalid")
    return value


def _stored_text(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise StoreIntegrityError(f"Stored {label} is invalid")
    return value


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _load_canonical_stored_json(
    raw: Any,
    label: str,
    *,
    maximum_bytes: int = MAX_DEFINITION_BYTES,
) -> Any:
    if type(raw) is not str or not raw or len(raw.encode("utf-8")) > maximum_bytes:
        raise StoreIntegrityError(f"Stored {label} exceeds the JSON byte ceiling")
    try:
        value = loads_json_without_duplicate_keys(raw)
    except (json.JSONDecodeError, DuplicateJsonKeyError) as exc:
        raise StoreIntegrityError(f"Stored {label} JSON is invalid") from exc
    try:
        canonical = _canonical_json(value)
    except ValueError as exc:
        raise StoreIntegrityError(f"Stored {label} JSON is invalid") from exc
    if canonical != raw:
        raise StoreIntegrityError(f"Stored {label} JSON is not canonical")
    return value


def _catalog_document(runtime_catalog: RuntimePackCatalog) -> dict[str, Any]:
    if type(runtime_catalog) is not RuntimePackCatalog:
        raise StoreError("A validated runtime pack catalog is required")
    document = runtime_catalog.to_dict()
    body = {key: item for key, item in document.items() if key != "catalog_sha256"}
    digest = _canonical_sha256({"domain": CATALOG_DOMAIN, "catalog": body})
    if document.get("catalog_sha256") != digest or runtime_catalog.catalog_sha256 != digest:
        raise StoreError("Runtime pack catalog identity is invalid")
    if len(runtime_catalog.packs) != document.get("coverage_summary", {}).get("runtime_pack_count"):
        raise StoreError("Runtime pack catalog coverage is invalid")
    return document


def _pack_for_profile(runtime_catalog: RuntimePackCatalog, profile_id: str) -> dict[str, Any]:
    _catalog_document(runtime_catalog)
    pack = runtime_catalog.pack_for_profile_id(profile_id)
    if pack is None:
        raise StoreError(f"Runtime profile {profile_id} is not in the validated catalog")
    return pack


def _cycle_check(work_ids: set[str], dependencies: Sequence[Mapping[str, str]]) -> None:
    incoming = {work_id: 0 for work_id in work_ids}
    outgoing: dict[str, list[str]] = {work_id: [] for work_id in work_ids}
    for edge in dependencies:
        work_id = edge["work_id"]
        dependency_id = edge["depends_on_work_id"]
        incoming[work_id] += 1
        outgoing[dependency_id].append(work_id)
    ready = sorted(work_id for work_id, count in incoming.items() if count == 0)
    visited = 0
    while ready:
        current = ready.pop(0)
        visited += 1
        for dependent in sorted(outgoing[current]):
            incoming[dependent] -= 1
            if incoming[dependent] == 0:
                ready.append(dependent)
                ready.sort()
    if visited != len(work_ids):
        raise StoreError("Workspace dependency graph contains a cycle")


@dataclass(frozen=True)
class ExpertWorkspaceDefinition:
    workspace_id: str
    workspace_sha256: str
    tenant_id: str
    mission_id: str
    plan_id: str
    runtime_catalog_sha256: str
    target_scope_sha256: str
    authority_snapshot_sha256: str
    evidence_snapshot_sha256: str
    assignments: tuple[Mapping[str, Any], ...]
    dependencies: tuple[Mapping[str, str], ...]
    review_requirements: tuple[Mapping[str, Any], ...]
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


@dataclass(frozen=True)
class ExpertWorkspaceState:
    workspace_id: str
    tenant_id: str
    mission_id: str
    plan_id: str
    revision: int
    status: str
    assignment_count: int
    completed_assignment_count: int


@dataclass(frozen=True)
class ExpertWorkspaceLeaseReceipt:
    lease_id: str
    workspace_id: str
    work_id: str
    attempt_number: int
    fencing_token: int
    envelope_id: str
    acquired_at: int
    expires_at: int
    workspace_revision: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "lease_id": self.lease_id,
            "workspace_id": self.workspace_id,
            "work_id": self.work_id,
            "attempt_number": self.attempt_number,
            "fencing_token": self.fencing_token,
            "envelope_id": self.envelope_id,
            "acquired_at": self.acquired_at,
            "expires_at": self.expires_at,
            "workspace_revision": self.workspace_revision,
            "automatic_retry_performed": False,
            "model_call_performed": False,
            "network_call_performed": False,
            "tool_effect": "none",
            "authorization_effect": "none",
        }


@dataclass(frozen=True)
class ExpertWorkspaceAcceptanceReceipt:
    acceptance_id: str
    workspace_id: str
    work_id: str
    attempt_number: int
    fencing_token: int
    product_id: str
    product_sha256: str
    product_type: str
    workspace_revision: int
    workspace_status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "acceptance_id": self.acceptance_id,
            "workspace_id": self.workspace_id,
            "work_id": self.work_id,
            "attempt_number": self.attempt_number,
            "fencing_token": self.fencing_token,
            "product_id": self.product_id,
            "product_sha256": self.product_sha256,
            "product_type": self.product_type,
            "workspace_revision": self.workspace_revision,
            "workspace_status": self.workspace_status,
            "review_status": "not_reviewed",
            "qualification_effect": "none",
            "authorization_effect": "none",
            "tool_effect": "none",
        }


@dataclass(frozen=True)
class ExpertWorkspaceVerificationReport:
    status: str
    schema_version: int
    workspace_count: int
    assignment_count: int
    lease_count: int
    product_count: int
    event_count: int
    store_sha256: str


def parse_expert_workspace_definition(
    raw: Any,
    runtime_catalog: RuntimePackCatalog,
) -> ExpertWorkspaceDefinition:
    value = _mapping(raw, "expert workspace definition")
    fields = {
        "schema_version",
        "workspace_id",
        "workspace_sha256",
        "tenant_id",
        "mission_id",
        "plan_id",
        "runtime_catalog_id",
        "runtime_catalog_version",
        "runtime_catalog_sha256",
        "target_scope_sha256",
        "authority_snapshot_sha256",
        "evidence_snapshot_sha256",
        "assignments",
        "dependencies",
        "review_requirements",
        "workspace_effect",
        "model_call_performed",
        "network_call_performed",
        "target_action_performed",
        "tool_effect",
        "qualification_effect",
        "authorization_effect",
    }
    _exact(value, fields, "expert workspace definition")
    if type(value.get("schema_version")) is not int or value.get("schema_version") != 1:
        raise StoreError("Workspace definition schema version is invalid")
    workspace_id = value.get("workspace_id")
    workspace_sha256 = _sha256(value.get("workspace_sha256"), "workspace_sha256")
    if not isinstance(workspace_id, str) or _WORKSPACE_ID_PATTERN.fullmatch(workspace_id) is None:
        raise StoreError("workspace_id is invalid")
    tenant_id = _identifier(value.get("tenant_id"), "tenant_id")
    mission_id = _identifier(value.get("mission_id"), "mission_id")
    plan_id = _identifier(value.get("plan_id"), "plan_id")
    catalog = _catalog_document(runtime_catalog)
    if (
        value.get("runtime_catalog_id") != catalog.get("catalog_id")
        or value.get("runtime_catalog_version") != catalog.get("catalog_version")
        or value.get("runtime_catalog_sha256") != runtime_catalog.catalog_sha256
    ):
        raise StoreError("Workspace runtime catalog identity is invalid")
    target_scope_sha256 = _sha256(value.get("target_scope_sha256"), "target_scope_sha256")
    authority_snapshot_sha256 = _sha256(
        value.get("authority_snapshot_sha256"), "authority_snapshot_sha256"
    )
    evidence_snapshot_sha256 = _sha256(
        value.get("evidence_snapshot_sha256"), "evidence_snapshot_sha256"
    )
    raw_assignments = value.get("assignments")
    if not isinstance(raw_assignments, list) or not 1 <= len(raw_assignments) <= MAX_ASSIGNMENTS:
        raise StoreError("Workspace assignments are invalid")
    assignments: list[dict[str, Any]] = []
    work_ids: set[str] = set()
    for index, raw_assignment in enumerate(raw_assignments):
        assignment = _mapping(raw_assignment, f"assignments[{index}]")
        _exact(
            assignment,
            {
                "work_id",
                "profile_id",
                "command_id",
                "runtime_pack_id",
                "runtime_pack_sha256",
                "maximum_attempts",
            },
            f"assignments[{index}]",
        )
        work_id = _identifier(assignment.get("work_id"), f"assignments[{index}].work_id")
        profile_id = _identifier(assignment.get("profile_id"), f"assignments[{index}].profile_id")
        if work_id in work_ids:
            raise StoreError("Workspace assignment work IDs must be unique")
        work_ids.add(work_id)
        pack = _pack_for_profile(runtime_catalog, profile_id)
        if (
            assignment.get("command_id") != pack["command_id"]
            or assignment.get("runtime_pack_id") != pack["runtime_pack_id"]
            or assignment.get("runtime_pack_sha256") != pack["runtime_pack_sha256"]
        ):
            raise StoreError("Workspace assignment does not match the exact runtime pack")
        maximum_attempts = _integer(
            assignment.get("maximum_attempts"),
            f"assignments[{index}].maximum_attempts",
            1,
            MAX_ATTEMPTS_PER_WORK,
        )
        assignments.append(
            {
                "work_id": work_id,
                "profile_id": profile_id,
                "command_id": pack["command_id"],
                "runtime_pack_id": pack["runtime_pack_id"],
                "runtime_pack_sha256": pack["runtime_pack_sha256"],
                "maximum_attempts": maximum_attempts,
            }
        )
    if assignments != sorted(assignments, key=lambda item: item["work_id"]):
        raise StoreError("Workspace assignments must be ordered by work_id")
    raw_dependencies = value.get("dependencies")
    if not isinstance(raw_dependencies, list) or len(raw_dependencies) > MAX_DEPENDENCIES:
        raise StoreError("Workspace dependencies are invalid")
    dependencies: list[dict[str, str]] = []
    dependency_keys: set[tuple[str, str]] = set()
    for index, raw_dependency in enumerate(raw_dependencies):
        dependency = _mapping(raw_dependency, f"dependencies[{index}]")
        _exact(dependency, {"work_id", "depends_on_work_id"}, f"dependencies[{index}]")
        work_id = _identifier(dependency.get("work_id"), f"dependencies[{index}].work_id")
        depends_on = _identifier(
            dependency.get("depends_on_work_id"),
            f"dependencies[{index}].depends_on_work_id",
        )
        if work_id not in work_ids or depends_on not in work_ids or work_id == depends_on:
            raise StoreError("Workspace dependency references are invalid")
        key = (work_id, depends_on)
        if key in dependency_keys:
            raise StoreError("Workspace dependencies contain duplicates")
        dependency_keys.add(key)
        dependencies.append({"work_id": work_id, "depends_on_work_id": depends_on})
    if dependencies != sorted(
        dependencies, key=lambda item: (item["work_id"], item["depends_on_work_id"])
    ):
        raise StoreError("Workspace dependencies must be ordered")
    _cycle_check(work_ids, dependencies)
    assignment_by_work = {item["work_id"]: item for item in assignments}
    for dependency in dependencies:
        parent_assignment = assignment_by_work[dependency["work_id"]]
        parent_pack = _pack_for_profile(runtime_catalog, str(parent_assignment["profile_id"]))
        command_members = parent_pack.get("command_member_profile_ids")
        dependency_profile = assignment_by_work[dependency["depends_on_work_id"]]["profile_id"]
        if command_members and dependency_profile not in command_members:
            raise StoreError("Commander dependency is outside its command membership")
    raw_reviews = value.get("review_requirements")
    if not isinstance(raw_reviews, list) or len(raw_reviews) != len(assignments):
        raise StoreError("Workspace review requirements must cover every assignment")
    reviews: list[dict[str, Any]] = []
    reviewed_work_ids: set[str] = set()
    for index, raw_review in enumerate(raw_reviews):
        review = _mapping(raw_review, f"review_requirements[{index}]")
        _exact(
            review,
            {"work_id", "required", "reviewer_profile_ids", "producer_excluded"},
            f"review_requirements[{index}]",
        )
        work_id = _identifier(review.get("work_id"), f"review_requirements[{index}].work_id")
        if work_id not in work_ids or work_id in reviewed_work_ids:
            raise StoreError("Workspace review requirement work IDs are invalid")
        reviewed_work_ids.add(work_id)
        required = review.get("required")
        producer_excluded = review.get("producer_excluded")
        reviewer_ids = review.get("reviewer_profile_ids")
        if not isinstance(required, bool) or producer_excluded is not True:
            raise StoreError("Workspace review requirement boundary is invalid")
        if (
            not isinstance(reviewer_ids, list)
            or len(reviewer_ids) > MAX_REVIEWERS_PER_WORK
            or (required and not reviewer_ids)
        ):
            raise StoreError("Workspace reviewer profile IDs are invalid")
        reviewers = tuple(_identifier(item, "reviewer_profile_id") for item in reviewer_ids)
        if any(
            _PROFILE_ID_PATTERN.fullmatch(item) is None
            or (
                not runtime_catalog.has_profile_id(item)
                and _HQ_PROFILE_ID_PATTERN.fullmatch(item) is None
            )
            for item in reviewers
        ):
            raise StoreError("Workspace reviewer profile IDs are invalid")
        if len(reviewers) != len(set(reviewers)) or tuple(sorted(reviewers)) != reviewers:
            raise StoreError("Workspace reviewer profile IDs must be unique and ordered")
        if assignment_by_work[work_id]["profile_id"] in reviewers:
            raise StoreError("Workspace producer cannot be its own reviewer")
        reviews.append(
            {
                "work_id": work_id,
                "required": required,
                "reviewer_profile_ids": list(reviewers),
                "producer_excluded": True,
            }
        )
    if reviews != sorted(reviews, key=lambda item: item["work_id"]):
        raise StoreError("Workspace review requirements must be ordered")
    expected_effects = {
        "workspace_effect": "durable_collaboration_only",
        "model_call_performed": False,
        "network_call_performed": False,
        "target_action_performed": False,
        "tool_effect": "none",
        "qualification_effect": "none",
        "authorization_effect": "none",
    }
    if any(
        type(value.get(field)) is not type(expected) or value.get(field) != expected
        for field, expected in expected_effects.items()
    ):
        raise StoreError("Workspace definition claims a prohibited effect")
    body = {
        key: item for key, item in value.items() if key not in {"workspace_id", "workspace_sha256"}
    }
    digest = _canonical_sha256({"domain": WORKSPACE_DOMAIN, "workspace": body})
    expected_id = f"EWS-{digest.removeprefix('sha256:')[:32].upper()}"
    if workspace_sha256 != digest or workspace_id != expected_id:
        raise StoreError("Workspace definition content address is invalid")
    canonical = _canonical_json(value)
    if len(canonical.encode("ascii")) > MAX_DEFINITION_BYTES:
        raise StoreError("Workspace definition exceeds the JSON byte ceiling")
    return ExpertWorkspaceDefinition(
        workspace_id=workspace_id,
        workspace_sha256=digest,
        tenant_id=tenant_id,
        mission_id=mission_id,
        plan_id=plan_id,
        runtime_catalog_sha256=runtime_catalog.catalog_sha256,
        target_scope_sha256=target_scope_sha256,
        authority_snapshot_sha256=authority_snapshot_sha256,
        evidence_snapshot_sha256=evidence_snapshot_sha256,
        assignments=tuple(_freeze_json(item) for item in assignments),
        dependencies=tuple(_freeze_json(item) for item in dependencies),
        review_requirements=tuple(_freeze_json(item) for item in reviews),
        document_json=canonical,
    )


def build_expert_workspace_definition(
    runtime_catalog: RuntimePackCatalog,
    *,
    tenant_id: str,
    mission_id: str,
    plan_id: str,
    target_scope_sha256: str,
    authority_snapshot_sha256: str,
    evidence_snapshot_sha256: str,
    assignments: Sequence[Mapping[str, Any]],
    dependencies: Sequence[Mapping[str, str]],
    review_requirements: Sequence[Mapping[str, Any]],
) -> ExpertWorkspaceDefinition:
    catalog = _catalog_document(runtime_catalog)
    body = {
        "schema_version": 1,
        "tenant_id": tenant_id,
        "mission_id": mission_id,
        "plan_id": plan_id,
        "runtime_catalog_id": catalog["catalog_id"],
        "runtime_catalog_version": catalog["catalog_version"],
        "runtime_catalog_sha256": runtime_catalog.catalog_sha256,
        "target_scope_sha256": target_scope_sha256,
        "authority_snapshot_sha256": authority_snapshot_sha256,
        "evidence_snapshot_sha256": evidence_snapshot_sha256,
        "assignments": [dict(item) for item in assignments],
        "dependencies": [dict(item) for item in dependencies],
        "review_requirements": [dict(item) for item in review_requirements],
        "workspace_effect": "durable_collaboration_only",
        "model_call_performed": False,
        "network_call_performed": False,
        "target_action_performed": False,
        "tool_effect": "none",
        "qualification_effect": "none",
        "authorization_effect": "none",
    }
    digest = _canonical_sha256({"domain": WORKSPACE_DOMAIN, "workspace": body})
    return parse_expert_workspace_definition(
        {
            **body,
            "workspace_id": f"EWS-{digest.removeprefix('sha256:')[:32].upper()}",
            "workspace_sha256": digest,
        },
        runtime_catalog,
    )


@runtime_checkable
class ExpertWorkspaceStoreAdapter(Protocol):
    """Provider-neutral durable workspace adapter boundary."""

    def initialize(self) -> None: ...

    def create_workspace(
        self,
        definition: ExpertWorkspaceDefinition,
        runtime_catalog: RuntimePackCatalog,
        *,
        created_at: int,
    ) -> ExpertWorkspaceState: ...

    def acquire_lease(
        self,
        workspace_id: str,
        *,
        tenant_id: str,
        expected_revision: int,
        envelope: Any,
        runtime_catalog: RuntimePackCatalog,
        acquired_at: int,
        lease_seconds: int,
    ) -> ExpertWorkspaceLeaseReceipt: ...

    def accept_work_product(
        self,
        workspace_id: str,
        *,
        tenant_id: str,
        expected_revision: int,
        lease_id: str,
        fencing_token: int,
        work_product: Any,
        runtime_catalog: RuntimePackCatalog,
        accepted_at: int,
    ) -> ExpertWorkspaceAcceptanceReceipt: ...

    def export_review_snapshot(
        self,
        workspace_id: str,
        *,
        runtime_catalog: RuntimePackCatalog,
        expert_registry: ExpertRegistry,
    ) -> ExpertReviewSnapshot: ...

    def apply_review_closure(
        self,
        verified: Any,
        *,
        authority: Any,
        authorization_token: bytes,
        mission_store_id: str,
        runtime_catalog: RuntimePackCatalog,
        expert_registry: ExpertRegistry,
        applied_at: int,
    ) -> ExpertWorkspaceClosureApplication: ...

    def apply_review_closure_revocation(
        self,
        verified: Any,
        *,
        authority: Any,
        authorization_token: bytes,
        runtime_catalog: RuntimePackCatalog,
        expert_registry: ExpertRegistry,
        applied_at: int,
    ) -> ExpertReviewClosureRevocation: ...

    def reconcile_review_records(
        self,
        records: ExpertReviewRecordSet,
        *,
        expert_registry: ExpertRegistry,
    ) -> ExpertReviewReconciliationReport: ...

    def verify_store(
        self,
        runtime_catalog: RuntimePackCatalog,
        *,
        expert_registry: ExpertRegistry | None = None,
    ) -> ExpertWorkspaceVerificationReport: ...


_SCHEMA_SQL_V1 = """
CREATE TABLE workspace_store_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE expert_workspaces (
    workspace_id TEXT PRIMARY KEY,
    workspace_sha256 TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    runtime_catalog_id TEXT NOT NULL,
    runtime_catalog_version TEXT NOT NULL,
    runtime_catalog_sha256 TEXT NOT NULL,
    target_scope_sha256 TEXT NOT NULL,
    authority_snapshot_sha256 TEXT NOT NULL,
    evidence_snapshot_sha256 TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    status TEXT NOT NULL CHECK (
        status IN ('active', 'products_complete_pending_review', 'completed')
    ),
    created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX expert_workspaces_tenant_mission_plan
ON expert_workspaces(tenant_id, mission_id, plan_id);
CREATE TABLE workspace_assignments (
    workspace_id TEXT NOT NULL REFERENCES expert_workspaces(workspace_id),
    work_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    runtime_pack_id TEXT NOT NULL,
    runtime_pack_sha256 TEXT NOT NULL,
    maximum_attempts INTEGER NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    fencing_token INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'completed')),
    terminal_product_id TEXT,
    PRIMARY KEY (workspace_id, work_id)
);
CREATE TABLE workspace_dependencies (
    workspace_id TEXT NOT NULL,
    work_id TEXT NOT NULL,
    depends_on_work_id TEXT NOT NULL,
    PRIMARY KEY (workspace_id, work_id, depends_on_work_id),
    FOREIGN KEY (workspace_id, work_id)
        REFERENCES workspace_assignments(workspace_id, work_id),
    FOREIGN KEY (workspace_id, depends_on_work_id)
        REFERENCES workspace_assignments(workspace_id, work_id)
);
CREATE TABLE workspace_review_requirements (
    workspace_id TEXT NOT NULL,
    work_id TEXT NOT NULL,
    required INTEGER NOT NULL CHECK (required IN (0, 1)),
    reviewer_profile_ids_json TEXT NOT NULL,
    producer_excluded INTEGER NOT NULL CHECK (producer_excluded = 1),
    PRIMARY KEY (workspace_id, work_id),
    FOREIGN KEY (workspace_id, work_id)
        REFERENCES workspace_assignments(workspace_id, work_id)
);
CREATE TABLE workspace_leases (
    lease_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    work_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    fencing_token INTEGER NOT NULL,
    envelope_id TEXT NOT NULL UNIQUE,
    envelope_sha256 TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    acquired_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'expired', 'completed')),
    UNIQUE (workspace_id, work_id, attempt_number),
    FOREIGN KEY (workspace_id, work_id)
        REFERENCES workspace_assignments(workspace_id, work_id)
);
CREATE TABLE workspace_products (
    product_id TEXT PRIMARY KEY,
    product_sha256 TEXT NOT NULL UNIQUE,
    workspace_id TEXT NOT NULL,
    work_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    lease_id TEXT NOT NULL UNIQUE REFERENCES workspace_leases(lease_id),
    producer_profile_id TEXT NOT NULL,
    product_type TEXT NOT NULL,
    command_id TEXT NOT NULL,
    envelope_id TEXT NOT NULL,
    product_json TEXT NOT NULL,
    accepted_at INTEGER NOT NULL,
    UNIQUE (workspace_id, work_id, attempt_number),
    FOREIGN KEY (workspace_id, work_id)
        REFERENCES workspace_assignments(workspace_id, work_id)
);
CREATE TABLE workspace_product_lineage (
    workspace_id TEXT NOT NULL REFERENCES expert_workspaces(workspace_id),
    product_id TEXT NOT NULL REFERENCES workspace_products(product_id),
    child_product_id TEXT NOT NULL REFERENCES workspace_products(product_id),
    PRIMARY KEY (workspace_id, product_id, child_product_id)
);
CREATE TABLE workspace_disagreements (
    workspace_id TEXT NOT NULL REFERENCES expert_workspaces(workspace_id),
    synthesis_product_id TEXT NOT NULL REFERENCES workspace_products(product_id),
    disagreement_index INTEGER NOT NULL,
    disagreement_json TEXT NOT NULL,
    PRIMARY KEY (workspace_id, synthesis_product_id, disagreement_index)
);
CREATE TABLE workspace_events (
    workspace_id TEXT NOT NULL REFERENCES expert_workspaces(workspace_id),
    sequence_number INTEGER NOT NULL,
    event_id TEXT NOT NULL UNIQUE,
    event_sha256 TEXT NOT NULL UNIQUE,
    previous_event_sha256 TEXT,
    event_type TEXT NOT NULL,
    workspace_revision INTEGER NOT NULL,
    occurred_at INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (workspace_id, sequence_number)
);
CREATE TRIGGER expert_workspaces_no_delete
BEFORE DELETE ON expert_workspaces BEGIN SELECT RAISE(ABORT, 'workspaces are append-only'); END;
CREATE TRIGGER expert_workspaces_core_immutable
BEFORE UPDATE OF workspace_sha256, tenant_id, mission_id, plan_id,
runtime_catalog_id, runtime_catalog_version, runtime_catalog_sha256,
target_scope_sha256, authority_snapshot_sha256, evidence_snapshot_sha256,
definition_json, created_at ON expert_workspaces
BEGIN SELECT RAISE(ABORT, 'workspace identity is immutable'); END;
CREATE TRIGGER expert_workspaces_revision_guard
BEFORE UPDATE OF revision ON expert_workspaces
WHEN NEW.revision != OLD.revision + 1
BEGIN SELECT RAISE(ABORT, 'workspace revision must advance by one'); END;
CREATE TRIGGER expert_workspaces_status_guard
BEFORE UPDATE OF status ON expert_workspaces
WHEN NOT (
    OLD.status = 'active'
    AND NEW.status IN ('active', 'products_complete_pending_review', 'completed')
)
BEGIN SELECT RAISE(ABORT, 'workspace terminal status is immutable'); END;
CREATE TRIGGER workspace_assignments_no_delete
BEFORE DELETE ON workspace_assignments
BEGIN SELECT RAISE(ABORT, 'assignments are append-only'); END;
CREATE TRIGGER workspace_assignments_core_immutable
BEFORE UPDATE OF profile_id, command_id, runtime_pack_id, runtime_pack_sha256,
maximum_attempts ON workspace_assignments
BEGIN SELECT RAISE(ABORT, 'assignment identity is immutable'); END;
CREATE TRIGGER workspace_dependencies_no_update
BEFORE UPDATE ON workspace_dependencies
BEGIN SELECT RAISE(ABORT, 'dependencies are immutable'); END;
CREATE TRIGGER workspace_dependencies_no_delete
BEFORE DELETE ON workspace_dependencies
BEGIN SELECT RAISE(ABORT, 'dependencies are append-only'); END;
CREATE TRIGGER workspace_reviews_no_update
BEFORE UPDATE ON workspace_review_requirements
BEGIN SELECT RAISE(ABORT, 'reviews are immutable'); END;
CREATE TRIGGER workspace_reviews_no_delete
BEFORE DELETE ON workspace_review_requirements
BEGIN SELECT RAISE(ABORT, 'reviews are append-only'); END;
CREATE TRIGGER workspace_leases_no_delete
BEFORE DELETE ON workspace_leases BEGIN SELECT RAISE(ABORT, 'leases are append-only'); END;
CREATE TRIGGER workspace_leases_core_immutable
BEFORE UPDATE OF lease_id, workspace_id, work_id, attempt_number, fencing_token,
envelope_id, envelope_sha256, envelope_json, acquired_at, expires_at ON workspace_leases
BEGIN SELECT RAISE(ABORT, 'lease identity is immutable'); END;
CREATE TRIGGER workspace_leases_status_guard
BEFORE UPDATE OF status ON workspace_leases
WHEN NOT (OLD.status = 'active' AND NEW.status IN ('expired', 'completed'))
BEGIN SELECT RAISE(ABORT, 'lease status transition is invalid'); END;
CREATE TRIGGER workspace_products_no_update
BEFORE UPDATE ON workspace_products BEGIN SELECT RAISE(ABORT, 'products are immutable'); END;
CREATE TRIGGER workspace_products_no_delete
BEFORE DELETE ON workspace_products BEGIN SELECT RAISE(ABORT, 'products are append-only'); END;
CREATE TRIGGER workspace_lineage_no_update
BEFORE UPDATE ON workspace_product_lineage BEGIN SELECT RAISE(ABORT, 'lineage is immutable'); END;
CREATE TRIGGER workspace_lineage_no_delete
BEFORE DELETE ON workspace_product_lineage BEGIN SELECT RAISE(ABORT, 'lineage is append-only'); END;
CREATE TRIGGER workspace_disagreements_no_update
BEFORE UPDATE ON workspace_disagreements
BEGIN SELECT RAISE(ABORT, 'disagreements are immutable'); END;
CREATE TRIGGER workspace_disagreements_no_delete
BEFORE DELETE ON workspace_disagreements
BEGIN SELECT RAISE(ABORT, 'disagreements are append-only'); END;
CREATE TRIGGER workspace_events_no_update
BEFORE UPDATE ON workspace_events BEGIN SELECT RAISE(ABORT, 'events are immutable'); END;
CREATE TRIGGER workspace_events_no_delete
BEFORE DELETE ON workspace_events BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
"""

_SCHEMA_SQL_V2 = """
CREATE TABLE workspace_review_closure_imports (
    closure_id TEXT PRIMARY KEY,
    closure_sha256 TEXT NOT NULL UNIQUE,
    snapshot_id TEXT NOT NULL,
    snapshot_sha256 TEXT NOT NULL,
    workspace_id TEXT NOT NULL UNIQUE REFERENCES expert_workspaces(workspace_id),
    mission_store_id TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK (
        disposition IN ('accepted', 'rejected', 'rework_required')
    ),
    snapshot_json TEXT NOT NULL,
    closure_json TEXT NOT NULL,
    application_id TEXT NOT NULL UNIQUE,
    application_sha256 TEXT NOT NULL UNIQUE,
    application_json TEXT NOT NULL,
    applied_at INTEGER NOT NULL,
    workspace_revision INTEGER NOT NULL,
    UNIQUE (workspace_id, workspace_revision)
);
CREATE TABLE workspace_review_closure_revocations (
    revocation_id TEXT PRIMARY KEY,
    revocation_sha256 TEXT NOT NULL UNIQUE,
    closure_id TEXT NOT NULL UNIQUE
        REFERENCES workspace_review_closure_imports(closure_id),
    closure_sha256 TEXT NOT NULL,
    workspace_id TEXT NOT NULL UNIQUE REFERENCES expert_workspaces(workspace_id),
    revocation_json TEXT NOT NULL,
    applied_at INTEGER NOT NULL,
    workspace_revision INTEGER NOT NULL,
    UNIQUE (workspace_id, workspace_revision)
);
CREATE TRIGGER workspace_closure_imports_no_update
BEFORE UPDATE ON workspace_review_closure_imports
BEGIN SELECT RAISE(ABORT, 'review closure imports are immutable'); END;
CREATE TRIGGER workspace_closure_imports_no_delete
BEFORE DELETE ON workspace_review_closure_imports
BEGIN SELECT RAISE(ABORT, 'review closure imports are append-only'); END;
CREATE TRIGGER workspace_closure_revocations_no_update
BEFORE UPDATE ON workspace_review_closure_revocations
BEGIN SELECT RAISE(ABORT, 'review closure revocations are immutable'); END;
CREATE TRIGGER workspace_closure_revocations_no_delete
BEFORE DELETE ON workspace_review_closure_revocations
BEGIN SELECT RAISE(ABORT, 'review closure revocations are append-only'); END;
"""

_SCHEMA_SQL_V3_COLUMN = """
ALTER TABLE workspace_store_identity ADD COLUMN store_id TEXT NOT NULL
DEFAULT 'EWI-00000000000000000000000000000000' CHECK (
    length(store_id) = 36
    AND substr(store_id, 1, 4) = 'EWI-'
    AND substr(store_id, 5) NOT GLOB '*[^0-9A-F]*'
);
"""

_SCHEMA_SQL_V3_GUARDS = """
CREATE UNIQUE INDEX workspace_store_identity_store_id
ON workspace_store_identity(store_id);
CREATE TRIGGER workspace_store_identity_immutable
BEFORE UPDATE ON workspace_store_identity
BEGIN SELECT RAISE(ABORT, 'workspace store identity is immutable'); END;
CREATE TRIGGER workspace_store_identity_no_delete
BEFORE DELETE ON workspace_store_identity
BEGIN SELECT RAISE(ABORT, 'workspace store identity cannot be deleted'); END;
"""

_SCHEMA_SQL_V3 = _SCHEMA_SQL_V3_COLUMN + _SCHEMA_SQL_V3_GUARDS

_SCHEMA_SQL = _SCHEMA_SQL_V1 + _SCHEMA_SQL_V2 + _SCHEMA_SQL_V3


def _schema_manifest(connection: sqlite3.Connection) -> tuple[tuple[str, str, str], ...]:
    rows = connection.execute(
        "SELECT type, name, sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    manifest: list[tuple[str, str, str]] = []
    for row in rows:
        statement = row["sql"] if isinstance(row, sqlite3.Row) else row[2]
        if not isinstance(statement, str):
            raise StoreIntegrityError("Expert workspace store schema SQL is invalid")
        manifest.append(
            (
                str(row["type"] if isinstance(row, sqlite3.Row) else row[0]),
                str(row["name"] if isinstance(row, sqlite3.Row) else row[1]),
                statement,
            )
        )
    return tuple(manifest)


def _build_expected_schema_manifest(schema_sql: str) -> tuple[tuple[str, str, str], ...]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(schema_sql)
        return _schema_manifest(connection)
    finally:
        connection.close()


_EXPECTED_SCHEMA_MANIFEST_V1 = _build_expected_schema_manifest(_SCHEMA_SQL_V1)
_EXPECTED_SCHEMA_MANIFEST_V2 = _build_expected_schema_manifest(
    _SCHEMA_SQL_V1 + _SCHEMA_SQL_V2
)
_EXPECTED_SCHEMA_MANIFEST = _build_expected_schema_manifest(_SCHEMA_SQL)


def _validated_workspace_row(
    row: sqlite3.Row,
    runtime_catalog: RuntimePackCatalog,
) -> ExpertWorkspaceDefinition:
    definition_document = _load_canonical_stored_json(
        row["definition_json"], "workspace definition"
    )
    definition = parse_expert_workspace_definition(definition_document, runtime_catalog)
    expected = {
        "workspace_id": definition.workspace_id,
        "workspace_sha256": definition.workspace_sha256,
        "tenant_id": definition.tenant_id,
        "mission_id": definition.mission_id,
        "plan_id": definition.plan_id,
        "runtime_catalog_id": definition_document["runtime_catalog_id"],
        "runtime_catalog_version": definition_document["runtime_catalog_version"],
        "runtime_catalog_sha256": definition.runtime_catalog_sha256,
        "target_scope_sha256": definition.target_scope_sha256,
        "authority_snapshot_sha256": definition.authority_snapshot_sha256,
        "evidence_snapshot_sha256": definition.evidence_snapshot_sha256,
    }
    if any(type(row[field]) is not str or row[field] != value for field, value in expected.items()):
        raise StoreIntegrityError("Stored workspace identity is inconsistent")
    _stored_integer(row["revision"], "workspace revision", 0, 2**63 - 1)
    _stored_integer(row["created_at"], "workspace creation time", 0, 2**63 - 1)
    if _stored_text(row["status"], "workspace status") not in {
        "active",
        "products_complete_pending_review",
        "completed",
    }:
        raise StoreIntegrityError("Stored workspace status is invalid")
    return definition


def _validated_assignment_row(
    row: sqlite3.Row,
    definition: ExpertWorkspaceDefinition,
) -> Mapping[str, Any]:
    work_id = _stored_text(row["work_id"], "assignment work_id")
    expected = next(
        (item for item in definition.assignments if item["work_id"] == work_id),
        None,
    )
    if expected is None:
        raise StoreIntegrityError("Stored assignment is absent from the workspace definition")
    immutable_fields = (
        "profile_id",
        "command_id",
        "runtime_pack_id",
        "runtime_pack_sha256",
    )
    if (
        type(row["workspace_id"]) is not str
        or row["workspace_id"] != definition.workspace_id
        or any(
            type(row[field]) is not str or row[field] != expected[field]
            for field in immutable_fields
        )
        or _stored_integer(
            row["maximum_attempts"],
            "assignment maximum_attempts",
            1,
            MAX_ATTEMPTS_PER_WORK,
        )
        != expected["maximum_attempts"]
    ):
        raise StoreIntegrityError("Stored assignment identity is inconsistent")
    attempt_count = _stored_integer(
        row["attempt_count"], "assignment attempt_count", 0, MAX_ATTEMPTS_PER_WORK
    )
    fencing_token = _stored_integer(
        row["fencing_token"], "assignment fencing_token", 0, MAX_ATTEMPTS_PER_WORK
    )
    if attempt_count != fencing_token:
        raise StoreIntegrityError("Stored assignment counters are inconsistent")
    status = _stored_text(row["status"], "assignment status")
    if status not in {
        "pending",
        "leased",
        "completed",
    }:
        raise StoreIntegrityError("Stored assignment status is invalid")
    terminal_product_id = row["terminal_product_id"]
    if terminal_product_id is not None and type(terminal_product_id) is not str:
        raise StoreIntegrityError("Stored assignment terminal product is invalid")
    if (
        (status == "pending" and (attempt_count != 0 or terminal_product_id is not None))
        or (status == "leased" and (attempt_count == 0 or terminal_product_id is not None))
        or (status == "completed" and (attempt_count == 0 or terminal_product_id is None))
    ):
        raise StoreIntegrityError("Stored assignment state is inconsistent")
    return expected


def _validated_review_import_row(
    row: sqlite3.Row,
    expert_registry: ExpertRegistry,
) -> tuple[
    ExpertReviewSnapshot,
    ExpertReviewClosureCertificate,
    ExpertWorkspaceClosureApplication,
]:
    try:
        snapshot = parse_expert_review_snapshot(
            _load_canonical_stored_json(
                row["snapshot_json"],
                "review snapshot",
                maximum_bytes=MAX_EXPERT_REVIEW_RECORD_BYTES,
            ),
            expert_registry,
        )
        closure = parse_expert_review_closure_certificate(
            _load_canonical_stored_json(
                row["closure_json"],
                "review closure",
                maximum_bytes=MAX_EXPERT_REVIEW_RECORD_BYTES,
            )
        )
        application = parse_expert_workspace_closure_application(
            _load_canonical_stored_json(
                row["application_json"],
                "closure application",
                maximum_bytes=MAX_EXPERT_REVIEW_RECORD_BYTES,
            )
        )
    except StoreError as exc:
        raise StoreIntegrityError("Stored workspace closure record is invalid") from exc
    snapshot_document = snapshot.to_dict()
    closure_document = closure.to_dict()
    application_document = application.to_dict()
    applied_at = _stored_integer(row["applied_at"], "closure application time", 0, 2**63 - 1)
    workspace_revision = _stored_integer(
        row["workspace_revision"], "closure workspace revision", 1, 2**63 - 1
    )
    expected_text = {
        "closure_id": closure.closure_id,
        "closure_sha256": closure.closure_sha256,
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "workspace_id": snapshot_document["workspace_id"],
        "mission_store_id": application_document["mission_store_id"],
        "disposition": closure_document["disposition"],
        "application_id": application.application_id,
        "application_sha256": application.application_sha256,
    }
    if (
        any(
            type(row[field]) is not str or row[field] != value
            for field, value in expected_text.items()
        )
        or closure_document["snapshot_id"] != snapshot.snapshot_id
        or closure_document["snapshot_sha256"] != snapshot.snapshot_sha256
        or application_document["workspace_id"] != snapshot_document["workspace_id"]
        or application_document["snapshot_id"] != snapshot.snapshot_id
        or application_document["snapshot_sha256"] != snapshot.snapshot_sha256
        or application_document["closure_id"] != closure.closure_id
        or application_document["closure_sha256"] != closure.closure_sha256
        or application_document["disposition"] != closure_document["disposition"]
        or application_document["workspace_revision_before"] != workspace_revision - 1
        or application_document["workspace_revision_after"] != workspace_revision
        or snapshot_document["workspace_revision"] != workspace_revision - 1
        or snapshot_document["event_count"] != workspace_revision
        or application_document["event_head_before_sha256"]
        != snapshot_document["event_head_sha256"]
        or application_document["applied_at"] != applied_at
        or closure_document["closed_at"] < snapshot_document["event_head_occurred_at"]
        or applied_at < closure_document["closed_at"]
    ):
        raise StoreIntegrityError("Stored workspace closure projection is inconsistent")
    return snapshot, closure, application


def _validated_review_revocation_row(
    row: sqlite3.Row,
    closure: ExpertReviewClosureCertificate,
    workspace_id: str,
) -> ExpertReviewClosureRevocation:
    try:
        revocation = parse_expert_review_closure_revocation(
            _load_canonical_stored_json(
                row["revocation_json"],
                "closure revocation",
                maximum_bytes=MAX_EXPERT_REVIEW_RECORD_BYTES,
            )
        )
    except StoreError as exc:
        raise StoreIntegrityError("Stored workspace closure revocation is invalid") from exc
    document = revocation.to_dict()
    closure_document = closure.to_dict()
    applied_at = _stored_integer(row["applied_at"], "revocation application time", 0, 2**63 - 1)
    _stored_integer(row["workspace_revision"], "revocation workspace revision", 1, 2**63 - 1)
    expected_text = {
        "revocation_id": revocation.revocation_id,
        "revocation_sha256": revocation.revocation_sha256,
        "closure_id": closure.closure_id,
        "closure_sha256": closure.closure_sha256,
        "workspace_id": workspace_id,
    }
    if (
        any(
            type(row[field]) is not str or row[field] != value
            for field, value in expected_text.items()
        )
        or document["closure_id"] != closure.closure_id
        or document["closure_sha256"] != closure.closure_sha256
        or document["revoked_at"] < closure_document["closed_at"]
        or applied_at < document["revoked_at"]
    ):
        raise StoreIntegrityError("Stored workspace revocation projection is inconsistent")
    return revocation


def _validate_review_projection_event(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    event_type: str,
    payload: Mapping[str, Any],
) -> None:
    workspace_id = _stored_text(row["workspace_id"], "projection workspace ID")
    revision = _stored_integer(
        row["workspace_revision"], "projection workspace revision", 1, 2**63 - 1
    )
    events = connection.execute(
        "SELECT * FROM workspace_events WHERE workspace_id = ? AND workspace_revision = ?",
        (workspace_id, revision),
    ).fetchall()
    prior = connection.execute(
        "SELECT event_sha256 FROM workspace_events WHERE workspace_id = ? AND sequence_number = ?",
        (workspace_id, revision - 1),
    ).fetchone()
    if len(events) != 1 or prior is None:
        raise StoreIntegrityError("Workspace review projection event is absent")
    event = events[0]
    occurred_at = _stored_integer(row["applied_at"], "projection application time", 0, 2**63 - 1)
    checked = _event_document(
        workspace_id,
        revision,
        _stored_text(prior["event_sha256"], "prior event SHA-256"),
        event_type,
        revision,
        occurred_at,
        payload,
    )
    if (
        _stored_integer(event["sequence_number"], "event sequence number", 1, 2**63 - 1) != revision
        or _stored_text(event["event_type"], "event type") != event_type
        or _stored_integer(event["workspace_revision"], "event revision", 1, 2**63 - 1) != revision
        or _stored_integer(event["occurred_at"], "event occurrence time", 0, 2**63 - 1)
        != occurred_at
        or _load_canonical_stored_json(event["payload_json"], "event payload") != dict(payload)
        or event["previous_event_sha256"] != checked["previous_event_sha256"]
        or event["event_id"] != checked["event_id"]
        or event["event_sha256"] != checked["event_sha256"]
    ):
        raise StoreIntegrityError("Workspace review projection event is inconsistent")


def _validated_review_projection_tail(
    connection: sqlite3.Connection,
    closure_row: sqlite3.Row,
    closure: ExpertReviewClosureCertificate,
) -> tuple[sqlite3.Row | None, ExpertReviewClosureRevocation | None]:
    workspace_id = _stored_text(closure_row["workspace_id"], "closure workspace ID")
    revocation_row = connection.execute(
        "SELECT * FROM workspace_review_closure_revocations WHERE workspace_id = ?",
        (workspace_id,),
    ).fetchone()
    revocation = None
    expected_revision = _stored_integer(
        closure_row["workspace_revision"], "closure workspace revision", 1, 2**63 - 1
    )
    if revocation_row is not None:
        revocation = _validated_review_revocation_row(revocation_row, closure, workspace_id)
        _validate_review_projection_event(
            connection,
            revocation_row,
            event_type="review_closure_revoked",
            payload={
                "closure_id": closure.closure_id,
                "closure_sha256": closure.closure_sha256,
                "revocation_id": revocation.revocation_id,
                "revocation_sha256": revocation.revocation_sha256,
            },
        )
        expected_revision += 1
        if (
            _stored_integer(
                revocation_row["workspace_revision"],
                "revocation workspace revision",
                1,
                2**63 - 1,
            )
            != expected_revision
        ):
            raise StoreIntegrityError("Workspace review projection tail is inconsistent")
    workspace = connection.execute(
        "SELECT revision FROM expert_workspaces WHERE workspace_id = ?",
        (workspace_id,),
    ).fetchone()
    event_count = connection.execute(
        "SELECT COUNT(*) FROM workspace_events WHERE workspace_id = ?",
        (workspace_id,),
    ).fetchone()
    if (
        workspace is None
        or event_count is None
        or _stored_integer(workspace["revision"], "workspace revision", 0, 2**63 - 1)
        != expected_revision
        or _stored_integer(event_count[0], "workspace event count", 1, 2**63 - 1)
        != expected_revision + 1
    ):
        raise StoreIntegrityError("Workspace review projection tail is inconsistent")
    return revocation_row, revocation


def _event_document(
    workspace_id: str,
    sequence_number: int,
    previous_event_sha256: str | None,
    event_type: str,
    workspace_revision: int,
    occurred_at: int,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    body = {
        "schema_version": 1,
        "workspace_id": workspace_id,
        "sequence_number": sequence_number,
        "previous_event_sha256": previous_event_sha256,
        "event_type": event_type,
        "workspace_revision": workspace_revision,
        "occurred_at": occurred_at,
        "payload": dict(payload),
    }
    digest = _canonical_sha256({"domain": EVENT_DOMAIN, "event": body})
    return {
        **body,
        "event_id": f"EWE-{digest.removeprefix('sha256:')[:32].upper()}",
        "event_sha256": digest,
    }


class SQLiteExpertWorkspaceStore:
    """SQLite reference adapter for durable expert collaboration state."""

    def __init__(self, path: str | Path, *, timeout_seconds: float = 10.0) -> None:
        self.path = Path(path)
        self.timeout_seconds = timeout_seconds

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            isolation_level=None,
            timeout=self.timeout_seconds,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            application_id, user_version = self._identity_headers(connection)
            if application_id == 0 and user_version == 0:
                existing = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1"
                ).fetchone()
                if existing is not None:
                    application_id, user_version = self._identity_headers(connection)
                    if application_id == 0 and user_version == 0:
                        raise StoreIntegrityError(
                            "Refusing to initialize a nonempty unclaimed workspace database"
                        )
            if application_id == 0 and user_version == 0:
                store_id = "EWI-" + secrets.token_hex(16).upper()
                try:
                    connection.executescript(
                        "BEGIN IMMEDIATE;\n"
                        + f"PRAGMA application_id = {APPLICATION_ID};\n"
                        + f"PRAGMA user_version = {SCHEMA_VERSION};\n"
                        + _SCHEMA_SQL
                        + "\nINSERT INTO workspace_store_identity"
                        + "(singleton, schema_version, created_at, store_id) "
                        + f"VALUES (1, {SCHEMA_VERSION}, 0, '{store_id}');"
                        + "\nCOMMIT;"
                    )
                except sqlite3.Error as exc:
                    connection.rollback()
                    try:
                        self._verify_identity(connection)
                    except (sqlite3.Error, StoreIntegrityError):
                        raise StoreIntegrityError(
                            "Expert workspace store initialization failed"
                        ) from exc
            elif application_id == APPLICATION_ID and user_version in {1, 2}:
                try:
                    self._verify_identity_version(connection, user_version)
                except (sqlite3.Error, StoreIntegrityError) as exc:
                    try:
                        self._verify_identity_version(connection, SCHEMA_VERSION)
                    except (sqlite3.Error, StoreIntegrityError):
                        raise StoreIntegrityError(
                            "Expert workspace store identity is invalid"
                        ) from exc
                    return
                store_id = "EWI-" + secrets.token_hex(16).upper()
                try:
                    additions = _SCHEMA_SQL_V2 if user_version == 1 else ""
                    connection.executescript(
                        "BEGIN IMMEDIATE;\n"
                        + additions
                        + _SCHEMA_SQL_V3_COLUMN
                        + "\nUPDATE workspace_store_identity "
                        + f"SET schema_version = 3, store_id = '{store_id}' "
                        + f"WHERE singleton = 1 AND schema_version = {user_version};\n"
                        + _SCHEMA_SQL_V3_GUARDS
                        + "\nPRAGMA user_version = 3;\nCOMMIT;"
                    )
                except sqlite3.Error as exc:
                    connection.rollback()
                    try:
                        self._verify_identity_version(connection, SCHEMA_VERSION)
                    except (sqlite3.Error, StoreIntegrityError):
                        raise StoreIntegrityError(
                            "Expert workspace store migration failed"
                        ) from exc
            elif application_id != APPLICATION_ID or user_version != SCHEMA_VERSION:
                raise StoreIntegrityError("Expert workspace store identity is invalid")
            try:
                self._verify_identity(connection)
            except sqlite3.Error as exc:
                raise StoreIntegrityError("Expert workspace store identity is invalid") from exc

    @staticmethod
    def _identity_headers(connection: sqlite3.Connection) -> tuple[int, int]:
        # One read statement prevents a concurrent commit from mixing headers
        # obtained by separate autocommit PRAGMA statements.
        row = connection.execute(
            "SELECT application_id, user_version "
            "FROM pragma_application_id(), pragma_user_version()"
        ).fetchone()
        return int(row[0]), int(row[1])

    @staticmethod
    def _verify_identity(connection: sqlite3.Connection) -> None:
        SQLiteExpertWorkspaceStore._verify_identity_version(connection, SCHEMA_VERSION)

    @staticmethod
    def _verify_identity_version(
        connection: sqlite3.Connection,
        schema_version: int,
    ) -> None:
        application_id, user_version = SQLiteExpertWorkspaceStore._identity_headers(connection)
        columns = "schema_version, created_at"
        if schema_version >= 3:
            columns += ", store_id"
        row = connection.execute(
            f"SELECT {columns} FROM workspace_store_identity WHERE singleton = 1"
        ).fetchone()
        if (
            application_id != APPLICATION_ID
            or user_version != schema_version
            or row is None
            or type(row["schema_version"]) is not int
            or row["schema_version"] != schema_version
            or type(row["created_at"]) is not int
            or row["created_at"] != 0
            or (
                schema_version >= 3
                and (
                    type(row["store_id"]) is not str
                    or re.fullmatch(r"EWI-[0-9A-F]{32}", row["store_id"]) is None
                )
            )
        ):
            raise StoreIntegrityError("Expert workspace store identity is invalid")
        actual_objects = {
            (str(item["type"]), str(item["name"]))
            for item in connection.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        expected_objects = (
            _EXPECTED_SCHEMA_OBJECTS_V1
            if schema_version == 1
            else (
                _EXPECTED_SCHEMA_OBJECTS_V2
                if schema_version == 2
                else _EXPECTED_SCHEMA_OBJECTS
            )
        )
        expected_manifest = (
            _EXPECTED_SCHEMA_MANIFEST_V1
            if schema_version == 1
            else (
                _EXPECTED_SCHEMA_MANIFEST_V2
                if schema_version == 2
                else _EXPECTED_SCHEMA_MANIFEST
            )
        )
        if actual_objects != expected_objects:
            raise StoreIntegrityError("Expert workspace store schema is invalid")
        if _schema_manifest(connection) != expected_manifest:
            raise StoreIntegrityError("Expert workspace store schema definition is invalid")

    @staticmethod
    def _append_event(
        connection: sqlite3.Connection,
        *,
        workspace_id: str,
        event_type: str,
        revision: int,
        occurred_at: int,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        last = connection.execute(
            "SELECT sequence_number, event_sha256 FROM workspace_events "
            "WHERE workspace_id = ? ORDER BY sequence_number DESC LIMIT 1",
            (workspace_id,),
        ).fetchone()
        sequence_number = (
            0
            if last is None
            else _stored_integer(last["sequence_number"], "event sequence_number", 0, 2**63 - 2) + 1
        )
        previous = None if last is None else _stored_text(last["event_sha256"], "event SHA-256")
        event = _event_document(
            workspace_id,
            sequence_number,
            previous,
            event_type,
            revision,
            occurred_at,
            payload,
        )
        connection.execute(
            "INSERT INTO workspace_events(workspace_id, sequence_number, event_id, "
            "event_sha256, previous_event_sha256, event_type, workspace_revision, "
            "occurred_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                workspace_id,
                sequence_number,
                event["event_id"],
                event["event_sha256"],
                previous,
                event_type,
                revision,
                occurred_at,
                _canonical_json(event["payload"]),
            ),
        )
        return event

    @staticmethod
    def _workspace_state(connection: sqlite3.Connection, workspace_id: str) -> ExpertWorkspaceState:
        row = connection.execute(
            "SELECT * FROM expert_workspaces WHERE workspace_id = ?", (workspace_id,)
        ).fetchone()
        if row is None:
            raise StoreError("Expert workspace does not exist")
        counts = connection.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed "
            "FROM workspace_assignments WHERE workspace_id = ?",
            (workspace_id,),
        ).fetchone()
        return ExpertWorkspaceState(
            workspace_id=workspace_id,
            tenant_id=_stored_text(row["tenant_id"], "workspace tenant_id"),
            mission_id=_stored_text(row["mission_id"], "workspace mission_id"),
            plan_id=_stored_text(row["plan_id"], "workspace plan_id"),
            revision=_stored_integer(row["revision"], "workspace revision", 0, 2**63 - 1),
            status=_stored_text(row["status"], "workspace status"),
            assignment_count=_stored_integer(
                counts["total"], "workspace assignment count", 0, MAX_ASSIGNMENTS
            ),
            completed_assignment_count=_stored_integer(
                counts["completed"] if counts["completed"] is not None else 0,
                "workspace completed assignment count",
                0,
                MAX_ASSIGNMENTS,
            ),
        )

    @staticmethod
    def _require_workspace(
        connection: sqlite3.Connection,
        workspace_id: str,
        tenant_id: str,
        expected_revision: int,
        runtime_catalog: RuntimePackCatalog,
    ) -> tuple[sqlite3.Row, ExpertWorkspaceDefinition]:
        row = connection.execute(
            "SELECT * FROM expert_workspaces WHERE workspace_id = ?", (workspace_id,)
        ).fetchone()
        if row is None:
            raise StoreError("Expert workspace does not exist")
        if row["tenant_id"] != tenant_id:
            raise StoreError("Expert workspace tenant binding is invalid")
        if (
            _stored_integer(row["revision"], "workspace revision", 0, 2**63 - 1)
            != expected_revision
        ):
            raise StoreConflictError("Expert workspace revision is stale")
        if row["status"] != "active":
            raise StoreConflictError("Expert workspace is terminal")
        definition = _validated_workspace_row(row, runtime_catalog)
        if definition.workspace_id != workspace_id:
            raise StoreIntegrityError("Stored workspace definition is inconsistent")
        return row, definition

    def create_workspace(
        self,
        definition: ExpertWorkspaceDefinition,
        runtime_catalog: RuntimePackCatalog,
        *,
        created_at: int,
    ) -> ExpertWorkspaceState:
        created_at = _integer(created_at, "created_at", 0, 2**63 - 1)
        if type(definition) is not ExpertWorkspaceDefinition:
            raise StoreError("A validated expert workspace definition is required")
        checked = parse_expert_workspace_definition(definition.to_dict(), runtime_catalog)
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._verify_identity(connection)
                count = _stored_integer(
                    connection.execute("SELECT COUNT(*) FROM expert_workspaces").fetchone()[0],
                    "workspace count",
                    0,
                    MAX_WORKSPACES,
                )
                if count >= MAX_WORKSPACES:
                    raise StoreError("Expert workspace count ceiling was reached")
                document = checked.to_dict()
                connection.execute(
                    "INSERT INTO expert_workspaces VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'active', ?)",
                    (
                        checked.workspace_id,
                        checked.workspace_sha256,
                        checked.tenant_id,
                        checked.mission_id,
                        checked.plan_id,
                        document["runtime_catalog_id"],
                        document["runtime_catalog_version"],
                        checked.runtime_catalog_sha256,
                        checked.target_scope_sha256,
                        checked.authority_snapshot_sha256,
                        checked.evidence_snapshot_sha256,
                        checked.document_json,
                        created_at,
                    ),
                )
                for assignment in checked.assignments:
                    connection.execute(
                        "INSERT INTO workspace_assignments(workspace_id, work_id, profile_id, "
                        "command_id, runtime_pack_id, runtime_pack_sha256, maximum_attempts, "
                        "status) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')",
                        (
                            checked.workspace_id,
                            assignment["work_id"],
                            assignment["profile_id"],
                            assignment["command_id"],
                            assignment["runtime_pack_id"],
                            assignment["runtime_pack_sha256"],
                            assignment["maximum_attempts"],
                        ),
                    )
                for dependency in checked.dependencies:
                    connection.execute(
                        "INSERT INTO workspace_dependencies VALUES (?, ?, ?)",
                        (
                            checked.workspace_id,
                            dependency["work_id"],
                            dependency["depends_on_work_id"],
                        ),
                    )
                for review in checked.review_requirements:
                    connection.execute(
                        "INSERT INTO workspace_review_requirements VALUES (?, ?, ?, ?, 1)",
                        (
                            checked.workspace_id,
                            review["work_id"],
                            int(review["required"]),
                            _canonical_json(review["reviewer_profile_ids"]),
                        ),
                    )
                self._append_event(
                    connection,
                    workspace_id=checked.workspace_id,
                    event_type="workspace_created",
                    revision=0,
                    occurred_at=created_at,
                    payload={"workspace_sha256": checked.workspace_sha256},
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise StoreConflictError("Expert workspace replay was rejected") from exc
            except (sqlite3.Error, StoreError):
                connection.rollback()
                raise
            return self._workspace_state(connection, checked.workspace_id)

    def get_workspace(self, workspace_id: str, *, tenant_id: str) -> ExpertWorkspaceState:
        with closing(self._connect()) as connection:
            self._verify_identity(connection)
            state = self._workspace_state(connection, workspace_id)
            if state.tenant_id != tenant_id:
                raise StoreError("Expert workspace tenant binding is invalid")
            return state

    def acquire_lease(
        self,
        workspace_id: str,
        *,
        tenant_id: str,
        expected_revision: int,
        envelope: Any,
        runtime_catalog: RuntimePackCatalog,
        acquired_at: int,
        lease_seconds: int,
    ) -> ExpertWorkspaceLeaseReceipt:
        expected_revision = _integer(expected_revision, "expected_revision", 0, 2**63 - 1)
        acquired_at = _integer(acquired_at, "acquired_at", 0, 2**63 - 1)
        lease_seconds = _integer(lease_seconds, "lease_seconds", 1, MAX_LEASE_SECONDS)
        if acquired_at > 2**63 - 1 - lease_seconds:
            raise StoreError("Lease expiry exceeds the integer ceiling")
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._verify_identity(connection)
                row, definition = self._require_workspace(
                    connection, workspace_id, tenant_id, expected_revision, runtime_catalog
                )
                last_event_time = _stored_integer(
                    connection.execute(
                        "SELECT occurred_at FROM workspace_events WHERE workspace_id = ? "
                        "ORDER BY sequence_number DESC LIMIT 1",
                        (workspace_id,),
                    ).fetchone()[0],
                    "event occurrence time",
                    0,
                    2**63 - 1,
                )
                if acquired_at < last_event_time:
                    raise StoreConflictError("Workspace event clock cannot move backward")
                raw_envelope = _mapping(envelope, "execution envelope")
                work_id = _identifier(raw_envelope.get("work_id"), "envelope work_id")
                assignment = connection.execute(
                    "SELECT * FROM workspace_assignments WHERE workspace_id = ? AND work_id = ?",
                    (workspace_id, work_id),
                ).fetchone()
                if assignment is None:
                    raise StoreError("Execution envelope is not assigned to this workspace")
                _validated_assignment_row(assignment, definition)
                attempt_count = _stored_integer(
                    assignment["attempt_count"],
                    "assignment attempt_count",
                    0,
                    MAX_ATTEMPTS_PER_WORK,
                )
                lease_history = connection.execute(
                    "SELECT attempt_number, fencing_token, status FROM workspace_leases "
                    "WHERE workspace_id = ? AND work_id = ? ORDER BY attempt_number",
                    (workspace_id, work_id),
                ).fetchall()
                if len(lease_history) != attempt_count or any(
                    _stored_integer(
                        item["attempt_number"],
                        "lease attempt_number",
                        1,
                        MAX_ATTEMPTS_PER_WORK,
                    )
                    != index
                    or _stored_integer(
                        item["fencing_token"],
                        "lease fencing_token",
                        1,
                        MAX_ATTEMPTS_PER_WORK,
                    )
                    != index
                    for index, item in enumerate(lease_history, start=1)
                ):
                    raise StoreIntegrityError("Stored assignment lease history is inconsistent")
                if lease_history and (
                    any(item["status"] != "expired" for item in lease_history[:-1])
                    or (
                        assignment["status"] == "leased" and lease_history[-1]["status"] != "active"
                    )
                ):
                    raise StoreIntegrityError("Stored assignment lease history is inconsistent")
                pack = _pack_for_profile(
                    runtime_catalog,
                    _stored_text(assignment["profile_id"], "assignment profile_id"),
                )
                parsed = parse_execution_envelope(raw_envelope, pack, runtime_catalog)
                if (
                    parsed.mission_id != definition.mission_id
                    or parsed.plan_id != definition.plan_id
                    or parsed.target_scope_sha256 != definition.target_scope_sha256
                    or parsed.authority_snapshot_sha256 != definition.authority_snapshot_sha256
                    or parsed.evidence_snapshot_sha256 != definition.evidence_snapshot_sha256
                    or parsed.profile_id != assignment["profile_id"]
                    or parsed.runtime_pack_id != assignment["runtime_pack_id"]
                    or parsed.runtime_pack_sha256 != assignment["runtime_pack_sha256"]
                ):
                    raise StoreError("Execution envelope does not match the workspace binding")
                if (
                    connection.execute(
                        "SELECT 1 FROM workspace_leases WHERE envelope_id = ?",
                        (parsed.envelope_id,),
                    ).fetchone()
                    is not None
                ):
                    raise StoreConflictError("Execution envelope replay was rejected")
                if assignment["status"] == "completed":
                    raise StoreConflictError("Workspace assignment is already terminal")
                incomplete = connection.execute(
                    "SELECT d.depends_on_work_id FROM workspace_dependencies d "
                    "JOIN workspace_assignments a ON a.workspace_id = d.workspace_id "
                    "AND a.work_id = d.depends_on_work_id "
                    "WHERE d.workspace_id = ? AND d.work_id = ? AND a.status != 'completed'",
                    (workspace_id, work_id),
                ).fetchall()
                if incomplete:
                    raise StoreConflictError("Workspace assignment dependencies are incomplete")
                active = connection.execute(
                    "SELECT * FROM workspace_leases WHERE workspace_id = ? AND work_id = ? "
                    "AND status = 'active' ORDER BY attempt_number DESC LIMIT 1",
                    (workspace_id, work_id),
                ).fetchone()
                if active is not None:
                    if (
                        _stored_integer(active["expires_at"], "lease expiry time", 0, 2**63 - 1)
                        > acquired_at
                    ):
                        raise StoreConflictError("Workspace assignment already has an active lease")
                    connection.execute(
                        "UPDATE workspace_leases SET status = 'expired' WHERE lease_id = ?",
                        (active["lease_id"],),
                    )
                attempt = (
                    _stored_integer(
                        assignment["attempt_count"],
                        "assignment attempt_count",
                        0,
                        MAX_ATTEMPTS_PER_WORK,
                    )
                    + 1
                )
                maximum_attempts = _stored_integer(
                    assignment["maximum_attempts"],
                    "assignment maximum_attempts",
                    1,
                    MAX_ATTEMPTS_PER_WORK,
                )
                if attempt > maximum_attempts:
                    raise StoreConflictError("Workspace assignment attempt ceiling was reached")
                token = (
                    _stored_integer(
                        assignment["fencing_token"],
                        "assignment fencing_token",
                        0,
                        MAX_ATTEMPTS_PER_WORK,
                    )
                    + 1
                )
                expires_at = acquired_at + lease_seconds
                lease_body = {
                    "workspace_id": workspace_id,
                    "work_id": work_id,
                    "attempt_number": attempt,
                    "fencing_token": token,
                    "envelope_id": parsed.envelope_id,
                    "envelope_sha256": parsed.envelope_sha256,
                    "acquired_at": acquired_at,
                    "expires_at": expires_at,
                }
                digest = _canonical_sha256({"domain": LEASE_DOMAIN, "lease": lease_body})
                lease_id = f"EWL-{digest.removeprefix('sha256:')[:32].upper()}"
                if _LEASE_ID_PATTERN.fullmatch(lease_id) is None:
                    raise StoreIntegrityError("Lease identity generation failed")
                connection.execute(
                    "INSERT INTO workspace_leases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')",
                    (
                        lease_id,
                        workspace_id,
                        work_id,
                        attempt,
                        token,
                        parsed.envelope_id,
                        parsed.envelope_sha256,
                        _canonical_json(raw_envelope),
                        acquired_at,
                        expires_at,
                    ),
                )
                connection.execute(
                    "UPDATE workspace_assignments SET attempt_count = ?, fencing_token = ?, "
                    "status = 'leased' WHERE workspace_id = ? AND work_id = ?",
                    (attempt, token, workspace_id, work_id),
                )
                revision = _stored_integer(row["revision"], "workspace revision", 0, 2**63 - 2) + 1
                connection.execute(
                    "UPDATE expert_workspaces SET revision = ? WHERE workspace_id = ?",
                    (revision, workspace_id),
                )
                self._append_event(
                    connection,
                    workspace_id=workspace_id,
                    event_type="lease_acquired",
                    revision=revision,
                    occurred_at=acquired_at,
                    payload={
                        "lease_id": lease_id,
                        "work_id": work_id,
                        "attempt_number": attempt,
                        "fencing_token": token,
                        "envelope_id": parsed.envelope_id,
                    },
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise StoreConflictError("Envelope or lease replay was rejected") from exc
            except (sqlite3.Error, StoreError):
                connection.rollback()
                raise
            return ExpertWorkspaceLeaseReceipt(
                lease_id=lease_id,
                workspace_id=workspace_id,
                work_id=work_id,
                attempt_number=attempt,
                fencing_token=token,
                envelope_id=parsed.envelope_id,
                acquired_at=acquired_at,
                expires_at=expires_at,
                workspace_revision=revision,
            )

    @staticmethod
    def _parsed_stored_product(
        connection: sqlite3.Connection,
        product_id: str,
        runtime_catalog: RuntimePackCatalog,
        cache: dict[str, WorkProduct],
        stack: set[str],
    ) -> WorkProduct:
        if product_id in cache:
            return cache[product_id]
        if product_id in stack:
            raise StoreIntegrityError("Stored product lineage contains a cycle")
        stack.add(product_id)
        row = connection.execute(
            "SELECT p.*, l.envelope_json, l.envelope_sha256 AS lease_envelope_sha256, "
            "l.workspace_id AS lease_workspace_id, l.work_id AS lease_work_id, "
            "l.attempt_number AS lease_attempt_number, l.acquired_at, l.expires_at "
            "FROM workspace_products p "
            "JOIN workspace_leases l ON l.lease_id = p.lease_id WHERE p.product_id = ?",
            (product_id,),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError("Stored product lineage is missing")
        product_attempt = _stored_integer(
            row["attempt_number"], "product attempt_number", 1, MAX_ATTEMPTS_PER_WORK
        )
        lease_attempt = _stored_integer(
            row["lease_attempt_number"], "lease attempt_number", 1, MAX_ATTEMPTS_PER_WORK
        )
        accepted_at = _stored_integer(row["accepted_at"], "product acceptance time", 0, 2**63 - 1)
        acquired_at = _stored_integer(row["acquired_at"], "lease acquisition time", 0, 2**63 - 1)
        expires_at = _stored_integer(row["expires_at"], "lease expiry time", 1, 2**63 - 1)
        if (
            row["workspace_id"] != row["lease_workspace_id"]
            or row["work_id"] != row["lease_work_id"]
            or product_attempt != lease_attempt
            or accepted_at < acquired_at
            or accepted_at >= expires_at
        ):
            raise StoreIntegrityError("Stored product lease binding is invalid")
        pack = _pack_for_profile(
            runtime_catalog,
            _stored_text(row["producer_profile_id"], "product producer_profile_id"),
        )
        raw_envelope = _load_canonical_stored_json(
            row["envelope_json"],
            "execution envelope",
            maximum_bytes=MAX_EXECUTION_ENVELOPE_BYTES,
        )
        envelope = parse_execution_envelope(raw_envelope, pack, runtime_catalog)
        if envelope.envelope_sha256 != row["lease_envelope_sha256"]:
            raise StoreIntegrityError("Stored execution envelope digest is invalid")
        raw_product = _load_canonical_stored_json(
            row["product_json"],
            "work product",
            maximum_bytes=MAX_WORK_PRODUCT_BYTES,
        )
        child_rows = connection.execute(
            "SELECT l.child_product_id, p.workspace_id AS child_workspace_id "
            "FROM workspace_product_lineage l JOIN workspace_products p "
            "ON p.product_id = l.child_product_id "
            "WHERE l.product_id = ? ORDER BY l.child_product_id",
            (product_id,),
        ).fetchall()
        if any(
            type(child["child_product_id"]) is not str
            or type(child["child_workspace_id"]) is not str
            or child["child_workspace_id"] != row["workspace_id"]
            for child in child_rows
        ):
            raise StoreIntegrityError("Stored product lineage crosses a workspace boundary")
        children = {
            _stored_text(
                child["child_product_id"], "child product_id"
            ): SQLiteExpertWorkspaceStore._parsed_stored_product(
                connection,
                _stored_text(child["child_product_id"], "child product_id"),
                runtime_catalog,
                cache,
                stack,
            )
            for child in child_rows
        }
        parsed = parse_work_product(
            raw_product,
            pack,
            envelope,
            runtime_catalog,
            child_products=children or None,
        )
        if (
            parsed.product_id != row["product_id"]
            or parsed.product_sha256 != row["product_sha256"]
            or parsed.product_type != row["product_type"]
            or parsed.work_id != row["work_id"]
            or parsed.envelope_id != row["envelope_id"]
            or pack["command_id"] != row["command_id"]
        ):
            raise StoreIntegrityError("Stored product columns do not match the product")
        cache[product_id] = parsed
        stack.remove(product_id)
        return parsed

    def accept_work_product(
        self,
        workspace_id: str,
        *,
        tenant_id: str,
        expected_revision: int,
        lease_id: str,
        fencing_token: int,
        work_product: Any,
        runtime_catalog: RuntimePackCatalog,
        accepted_at: int,
    ) -> ExpertWorkspaceAcceptanceReceipt:
        expected_revision = _integer(expected_revision, "expected_revision", 0, 2**63 - 1)
        accepted_at = _integer(accepted_at, "accepted_at", 0, 2**63 - 1)
        fencing_token = _integer(fencing_token, "fencing_token", 1, 2**63 - 1)
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._verify_identity(connection)
                workspace_row, definition = self._require_workspace(
                    connection, workspace_id, tenant_id, expected_revision, runtime_catalog
                )
                lease = connection.execute(
                    "SELECT * FROM workspace_leases WHERE lease_id = ? AND workspace_id = ?",
                    (lease_id, workspace_id),
                ).fetchone()
                if lease is None:
                    raise StoreError("Workspace lease does not exist")
                lease_fencing_token = _stored_integer(
                    lease["fencing_token"], "lease fencing_token", 1, MAX_ATTEMPTS_PER_WORK
                )
                lease_attempt = _stored_integer(
                    lease["attempt_number"], "lease attempt_number", 1, MAX_ATTEMPTS_PER_WORK
                )
                lease_expiry = _stored_integer(
                    lease["expires_at"], "lease expiry time", 1, 2**63 - 1
                )
                if (
                    type(lease["workspace_id"]) is not str
                    or lease["workspace_id"] != workspace_id
                    or type(lease["work_id"]) is not str
                    or lease["status"] != "active"
                    or lease_attempt != lease_fencing_token
                    or lease_fencing_token != fencing_token
                    or lease_expiry <= accepted_at
                ):
                    raise StoreConflictError("Workspace lease or fencing token is stale")
                last_event_time = _stored_integer(
                    connection.execute(
                        "SELECT occurred_at FROM workspace_events WHERE workspace_id = ? "
                        "ORDER BY sequence_number DESC LIMIT 1",
                        (workspace_id,),
                    ).fetchone()[0],
                    "event occurrence time",
                    0,
                    2**63 - 1,
                )
                lease_acquired_at = _stored_integer(
                    lease["acquired_at"], "lease acquisition time", 0, 2**63 - 1
                )
                if accepted_at < lease_acquired_at or accepted_at < last_event_time:
                    raise StoreConflictError("Workspace event clock cannot move backward")
                assignment = connection.execute(
                    "SELECT * FROM workspace_assignments WHERE workspace_id = ? AND work_id = ?",
                    (workspace_id, lease["work_id"]),
                ).fetchone()
                if assignment is None:
                    raise StoreIntegrityError("Workspace assignment lease state is inconsistent")
                _validated_assignment_row(assignment, definition)
                if (
                    _stored_integer(
                        assignment["fencing_token"],
                        "assignment fencing_token",
                        0,
                        MAX_ATTEMPTS_PER_WORK,
                    )
                    != fencing_token
                ):
                    raise StoreIntegrityError("Workspace assignment lease state is inconsistent")
                pack = _pack_for_profile(
                    runtime_catalog,
                    _stored_text(assignment["profile_id"], "assignment profile_id"),
                )
                raw_envelope = _load_canonical_stored_json(
                    lease["envelope_json"],
                    "execution envelope",
                    maximum_bytes=MAX_EXECUTION_ENVELOPE_BYTES,
                )
                envelope = parse_execution_envelope(raw_envelope, pack, runtime_catalog)
                if envelope.envelope_sha256 != lease["envelope_sha256"]:
                    raise StoreIntegrityError("Stored execution envelope digest is invalid")
                if (
                    envelope.mission_id != definition.mission_id
                    or envelope.plan_id != definition.plan_id
                    or envelope.target_scope_sha256 != definition.target_scope_sha256
                    or envelope.authority_snapshot_sha256 != definition.authority_snapshot_sha256
                    or envelope.evidence_snapshot_sha256 != definition.evidence_snapshot_sha256
                ):
                    raise StoreIntegrityError("Stored execution envelope binding is invalid")
                raw_product = _mapping(work_product, "expert work product")
                lineage = raw_product.get("lineage_product_ids")
                if not isinstance(lineage, list) or len(lineage) > MAX_DEPENDENCIES:
                    raise StoreError("Work product lineage is invalid")
                child_products: dict[str, WorkProduct] = {}
                for child_id in lineage:
                    if not isinstance(child_id, str):
                        raise StoreError("Work product lineage identity is invalid")
                    child_row = connection.execute(
                        "SELECT workspace_id FROM workspace_products WHERE product_id = ?",
                        (child_id,),
                    ).fetchone()
                    if child_row is None or child_row["workspace_id"] != workspace_id:
                        raise StoreError("Work product lineage crosses a workspace boundary")
                    child_products[child_id] = self._parsed_stored_product(
                        connection, child_id, runtime_catalog, {}, set()
                    )
                parsed = parse_work_product(
                    raw_product,
                    pack,
                    envelope,
                    runtime_catalog,
                    child_products=child_products or None,
                )
                if parsed.producer_profile_id != assignment["profile_id"]:
                    raise StoreError("Work product producer is not the assigned profile")
                dependency_rows = connection.execute(
                    "SELECT a.terminal_product_id FROM workspace_dependencies d "
                    "JOIN workspace_assignments a ON a.workspace_id = d.workspace_id "
                    "AND a.work_id = d.depends_on_work_id "
                    "WHERE d.workspace_id = ? AND d.work_id = ? ORDER BY d.depends_on_work_id",
                    (workspace_id, assignment["work_id"]),
                ).fetchall()
                dependency_products = {
                    _stored_text(item["terminal_product_id"], "dependency terminal product_id")
                    for item in dependency_rows
                    if item["terminal_product_id"] is not None
                }
                if parsed.product_type == "commander_synthesis":
                    if set(lineage) != dependency_products:
                        raise StoreError(
                            "Commander synthesis must bind every dependency terminal product"
                        )
                elif lineage:
                    raise StoreError("Specialist work products cannot claim synthesis lineage")
                for child in child_products.values():
                    if (
                        child.mission_id != definition.mission_id
                        or child.plan_id != definition.plan_id
                        or child.target_scope_sha256 != definition.target_scope_sha256
                        or child.authority_snapshot_sha256 != definition.authority_snapshot_sha256
                        or child.evidence_snapshot_sha256 != definition.evidence_snapshot_sha256
                    ):
                        raise StoreError("Work product lineage crosses a workspace boundary")
                review_row = connection.execute(
                    "SELECT * FROM workspace_review_requirements "
                    "WHERE workspace_id = ? AND work_id = ?",
                    (workspace_id, assignment["work_id"]),
                ).fetchone()
                if review_row is None:
                    raise StoreIntegrityError("Workspace review requirement is missing")
                expected_review = next(
                    item
                    for item in definition.review_requirements
                    if item["work_id"] == assignment["work_id"]
                )
                stored_reviewer_ids = _load_canonical_stored_json(
                    review_row["reviewer_profile_ids_json"],
                    "reviewer profile IDs",
                )
                stored_required = _stored_integer(
                    review_row["required"], "review required flag", 0, 1
                )
                stored_producer_excluded = _stored_integer(
                    review_row["producer_excluded"], "producer exclusion flag", 1, 1
                )
                if (
                    type(review_row["workspace_id"]) is not str
                    or review_row["workspace_id"] != definition.workspace_id
                    or type(review_row["work_id"]) is not str
                    or review_row["work_id"] != assignment["work_id"]
                    or bool(stored_required) is not expected_review["required"]
                    or stored_reviewer_ids != list(expected_review["reviewer_profile_ids"])
                    or stored_producer_excluded != 1
                ):
                    raise StoreIntegrityError("Stored review requirement is inconsistent")
                review = raw_product.get("independent_review")
                if not isinstance(review, Mapping) or review.get("status") != "not_reviewed":
                    raise StoreError("Work product cannot claim completed review")
                if review.get("required") is not bool(stored_required):
                    raise StoreError("Work product review requirement does not match the workspace")
                connection.execute(
                    "INSERT INTO workspace_products VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        parsed.product_id,
                        parsed.product_sha256,
                        workspace_id,
                        parsed.work_id,
                        _stored_integer(
                            lease["attempt_number"],
                            "lease attempt_number",
                            1,
                            MAX_ATTEMPTS_PER_WORK,
                        ),
                        lease_id,
                        parsed.producer_profile_id,
                        parsed.product_type,
                        assignment["command_id"],
                        parsed.envelope_id,
                        parsed.document_json,
                        accepted_at,
                    ),
                )
                for child_id in sorted(child_products):
                    connection.execute(
                        "INSERT INTO workspace_product_lineage VALUES (?, ?, ?)",
                        (workspace_id, parsed.product_id, child_id),
                    )
                disagreements = (
                    parsed.to_dict()["payload"].get("disagreements", [])
                    if parsed.product_type == "commander_synthesis"
                    else []
                )
                for index, disagreement in enumerate(disagreements):
                    connection.execute(
                        "INSERT INTO workspace_disagreements VALUES (?, ?, ?, ?)",
                        (
                            workspace_id,
                            parsed.product_id,
                            index,
                            _canonical_json(disagreement),
                        ),
                    )
                connection.execute(
                    "UPDATE workspace_leases SET status = 'completed' WHERE lease_id = ?",
                    (lease_id,),
                )
                connection.execute(
                    "UPDATE workspace_assignments SET status = 'completed', "
                    "terminal_product_id = ? WHERE workspace_id = ? AND work_id = ?",
                    (parsed.product_id, workspace_id, parsed.work_id),
                )
                remaining = _stored_integer(
                    connection.execute(
                        "SELECT COUNT(*) FROM workspace_assignments "
                        "WHERE workspace_id = ? AND status != 'completed'",
                        (workspace_id,),
                    ).fetchone()[0],
                    "remaining assignment count",
                    0,
                    MAX_ASSIGNMENTS,
                )
                required_review_count = _stored_integer(
                    connection.execute(
                        "SELECT COUNT(*) FROM workspace_review_requirements "
                        "WHERE workspace_id = ? AND required = 1",
                        (workspace_id,),
                    ).fetchone()[0],
                    "required review count",
                    0,
                    MAX_ASSIGNMENTS,
                )
                if remaining:
                    workspace_status = "active"
                elif required_review_count:
                    workspace_status = "products_complete_pending_review"
                else:
                    workspace_status = "completed"
                revision = (
                    _stored_integer(workspace_row["revision"], "workspace revision", 0, 2**63 - 2)
                    + 1
                )
                connection.execute(
                    "UPDATE expert_workspaces SET revision = ?, status = ? WHERE workspace_id = ?",
                    (revision, workspace_status, workspace_id),
                )
                self._append_event(
                    connection,
                    workspace_id=workspace_id,
                    event_type="work_product_accepted",
                    revision=revision,
                    occurred_at=accepted_at,
                    payload={
                        "lease_id": lease_id,
                        "work_id": parsed.work_id,
                        "attempt_number": _stored_integer(
                            lease["attempt_number"],
                            "lease attempt_number",
                            1,
                            MAX_ATTEMPTS_PER_WORK,
                        ),
                        "fencing_token": fencing_token,
                        "product_id": parsed.product_id,
                        "product_sha256": parsed.product_sha256,
                        "product_type": parsed.product_type,
                        "workspace_status": workspace_status,
                    },
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise StoreConflictError("Terminal product or product replay was rejected") from exc
            except (sqlite3.Error, StoreError):
                connection.rollback()
                raise
            acceptance_body = {
                "workspace_id": workspace_id,
                "work_id": parsed.work_id,
                "attempt_number": _stored_integer(
                    lease["attempt_number"],
                    "lease attempt_number",
                    1,
                    MAX_ATTEMPTS_PER_WORK,
                ),
                "fencing_token": fencing_token,
                "product_id": parsed.product_id,
                "product_sha256": parsed.product_sha256,
                "workspace_revision": revision,
            }
            digest = _canonical_sha256({"domain": ACCEPTANCE_DOMAIN, "acceptance": acceptance_body})
            return ExpertWorkspaceAcceptanceReceipt(
                acceptance_id=f"EWA-{digest.removeprefix('sha256:')[:32].upper()}",
                workspace_id=workspace_id,
                work_id=parsed.work_id,
                attempt_number=_stored_integer(
                    lease["attempt_number"],
                    "lease attempt_number",
                    1,
                    MAX_ATTEMPTS_PER_WORK,
                ),
                fencing_token=fencing_token,
                product_id=parsed.product_id,
                product_sha256=parsed.product_sha256,
                product_type=parsed.product_type,
                workspace_revision=revision,
                workspace_status=workspace_status,
            )

    @staticmethod
    def _review_snapshot_from_connection(
        connection: sqlite3.Connection,
        workspace_id: str,
        runtime_catalog: RuntimePackCatalog,
        expert_registry: ExpertRegistry,
    ) -> ExpertReviewSnapshot:
        workspace = connection.execute(
            "SELECT * FROM expert_workspaces WHERE workspace_id = ?",
            (workspace_id,),
        ).fetchone()
        if workspace is None:
            raise StoreError("Expert workspace does not exist")
        definition = _validated_workspace_row(workspace, runtime_catalog)
        if workspace["status"] != "products_complete_pending_review":
            raise StoreConflictError("Expert workspace is not pending independent review")
        assignments = connection.execute(
            "SELECT * FROM workspace_assignments WHERE workspace_id = ? ORDER BY work_id",
            (workspace_id,),
        ).fetchall()
        if not assignments or any(item["status"] != "completed" for item in assignments):
            raise StoreConflictError("Expert workspace products are incomplete")
        review_rows = {
            item["work_id"]: item
            for item in connection.execute(
                "SELECT * FROM workspace_review_requirements WHERE workspace_id = ?",
                (workspace_id,),
            ).fetchall()
        }
        products: list[dict[str, Any]] = []
        slots: list[dict[str, Any]] = []
        producer_by_product: dict[str, str] = {}
        raw_products: list[tuple[sqlite3.Row, sqlite3.Row, sqlite3.Row]] = []
        for assignment in assignments:
            product = connection.execute(
                "SELECT p.*, l.envelope_sha256, l.fencing_token "
                "FROM workspace_products p JOIN workspace_leases l ON l.lease_id = p.lease_id "
                "WHERE p.workspace_id = ? AND p.work_id = ?",
                (workspace_id, assignment["work_id"]),
            ).fetchone()
            review = review_rows.get(assignment["work_id"])
            if product is None or review is None:
                raise StoreIntegrityError("Workspace review snapshot source is incomplete")
            producer_by_product[product["product_id"]] = _stored_text(
                product["producer_profile_id"], "product producer profile"
            )
            raw_products.append((assignment, product, review))

        def lineage_producers(product_id: str) -> set[str]:
            producers: set[str] = set()
            expanded: set[str] = set()
            pending = [product_id]
            while pending:
                parent_id = pending.pop()
                children = [
                    _stored_text(item["child_product_id"], "lineage product ID")
                    for item in connection.execute(
                        "SELECT child_product_id FROM workspace_product_lineage "
                        "WHERE workspace_id = ? AND product_id = ?",
                        (workspace_id, parent_id),
                    ).fetchall()
                ]
                for child_id in children:
                    if child_id == product_id:
                        raise StoreIntegrityError("Stored review lineage contains a cycle")
                    producer = producer_by_product.get(child_id)
                    if producer is None:
                        raise StoreIntegrityError("Stored review lineage producer is absent")
                    producers.add(producer)
                    if child_id not in expanded:
                        pending.append(child_id)
                expanded.add(parent_id)
            return producers

        for assignment, product, review in raw_products:
            dependency_rows = connection.execute(
                "SELECT a.terminal_product_id FROM workspace_dependencies d "
                "JOIN workspace_assignments a ON a.workspace_id = d.workspace_id "
                "AND a.work_id = d.depends_on_work_id "
                "WHERE d.workspace_id = ? AND d.work_id = ? ORDER BY d.depends_on_work_id",
                (workspace_id, assignment["work_id"]),
            ).fetchall()
            dependencies = [
                _stored_text(item["terminal_product_id"], "dependency product ID")
                for item in dependency_rows
            ]
            lineage = [
                _stored_text(item["child_product_id"], "lineage product ID")
                for item in connection.execute(
                    "SELECT child_product_id FROM workspace_product_lineage "
                    "WHERE workspace_id = ? AND product_id = ? ORDER BY child_product_id",
                    (workspace_id, product["product_id"]),
                ).fetchall()
            ]
            disagreement_sha256s = [
                _canonical_sha256(
                    _load_canonical_stored_json(item["disagreement_json"], "commander disagreement")
                )
                for item in connection.execute(
                    "SELECT disagreement_json FROM workspace_disagreements "
                    "WHERE workspace_id = ? AND synthesis_product_id = ? "
                    "ORDER BY disagreement_index",
                    (workspace_id, product["product_id"]),
                ).fetchall()
            ]
            required = bool(_stored_integer(review["required"], "review required flag", 0, 1))
            product_document = {
                "work_id": _stored_text(product["work_id"], "product work ID"),
                "producer_profile_id": _stored_text(
                    product["producer_profile_id"], "product producer profile"
                ),
                "command_id": _stored_text(product["command_id"], "product command ID"),
                "product_id": _stored_text(product["product_id"], "product ID"),
                "product_sha256": _stored_text(product["product_sha256"], "product SHA-256"),
                "product_type": _stored_text(product["product_type"], "product type"),
                "envelope_id": _stored_text(product["envelope_id"], "envelope ID"),
                "envelope_sha256": _stored_text(product["envelope_sha256"], "envelope SHA-256"),
                "attempt_number": _stored_integer(
                    product["attempt_number"],
                    "product attempt number",
                    1,
                    MAX_ATTEMPTS_PER_WORK,
                ),
                "fencing_token": _stored_integer(
                    product["fencing_token"],
                    "product fencing token",
                    1,
                    MAX_ATTEMPTS_PER_WORK,
                ),
                "review_required": required,
                "dependency_product_ids": dependencies,
                "lineage_product_ids": lineage,
                "disagreement_sha256s": disagreement_sha256s,
            }
            products.append(product_document)
            if required:
                reviewer_ids = _load_canonical_stored_json(
                    review["reviewer_profile_ids_json"], "reviewer profile IDs"
                )
                if not isinstance(reviewer_ids, list):
                    raise StoreIntegrityError("Stored reviewer profile IDs are invalid")
                excluded = {product_document["producer_profile_id"]}
                excluded.update(lineage_producers(product_document["product_id"]))
                for reviewer_id in reviewer_ids:
                    binding = derive_reviewer_role(expert_registry, reviewer_id)
                    slots.append(
                        {
                            "work_id": product_document["work_id"],
                            "product_id": product_document["product_id"],
                            "product_sha256": product_document["product_sha256"],
                            **binding,
                            "producer_profile_ids_excluded": sorted(excluded),
                        }
                    )
        event = connection.execute(
            "SELECT event_sha256, occurred_at FROM workspace_events WHERE workspace_id = ? "
            "ORDER BY sequence_number DESC LIMIT 1",
            (workspace_id,),
        ).fetchone()
        if event is None:
            raise StoreIntegrityError("Workspace event chain is absent")
        policy_body = {
            "all_slots_mandatory": True,
            "decision_precedence": ["rejected", "rework_required", "accepted"],
            "policy_id": "sunderkey.expert-review-policy.v1",
            "producer_and_lineage_excluded": True,
            "schema_version": 1,
        }
        registry_sha256 = _canonical_sha256(expert_registry.to_dict())
        snapshot_body = {
            "schema_version": 1,
            "kind": "expert_review_snapshot",
            "tenant_id": definition.tenant_id,
            "mission_id": definition.mission_id,
            "plan_id": definition.plan_id,
            "workspace_id": definition.workspace_id,
            "workspace_sha256": definition.workspace_sha256,
            "workspace_schema_version": SCHEMA_VERSION,
            "workspace_revision": _stored_integer(
                workspace["revision"], "workspace revision", 0, 2**63 - 1
            ),
            "workspace_status": workspace["status"],
            "runtime_catalog_id": definition.to_dict()["runtime_catalog_id"],
            "runtime_catalog_version": definition.to_dict()["runtime_catalog_version"],
            "runtime_catalog_sha256": definition.runtime_catalog_sha256,
            "registry_sha256": registry_sha256,
            "target_scope_sha256": definition.target_scope_sha256,
            "authority_snapshot_sha256": definition.authority_snapshot_sha256,
            "evidence_snapshot_sha256": definition.evidence_snapshot_sha256,
            "event_count": _stored_integer(
                connection.execute(
                    "SELECT COUNT(*) FROM workspace_events WHERE workspace_id = ?",
                    (workspace_id,),
                ).fetchone()[0],
                "event count",
                1,
                2**63 - 1,
            ),
            "event_head_sha256": _stored_text(event["event_sha256"], "event head SHA-256"),
            "event_head_occurred_at": _stored_integer(
                event["occurred_at"], "event head occurrence time", 0, 2**63 - 1
            ),
            "products": sorted(products, key=lambda item: item["work_id"]),
            "review_slots": sorted(
                slots, key=lambda item: (item["work_id"], item["reviewer_profile_id"])
            ),
            "review_policy": {
                **policy_body,
                "policy_sha256": _canonical_sha256(policy_body),
            },
            "effects": {
                "authorization_effect": "none",
                "model_call_performed": False,
                "network_call_performed": False,
                "qualification_effect": "none",
                "target_action_performed": False,
                "tool_effect": "none",
            },
        }
        return build_expert_review_snapshot(snapshot_body, expert_registry)

    def export_review_snapshot(
        self,
        workspace_id: str,
        *,
        runtime_catalog: RuntimePackCatalog,
        expert_registry: ExpertRegistry,
    ) -> ExpertReviewSnapshot:
        self.verify_store(runtime_catalog, expert_registry=expert_registry)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            self._verify_identity(connection)
            if (
                connection.execute(
                    "SELECT 1 FROM workspace_review_closure_imports WHERE workspace_id = ?",
                    (workspace_id,),
                ).fetchone()
                is not None
            ):
                raise StoreConflictError("Expert workspace review snapshot is already closed")
            return self._review_snapshot_from_connection(
                connection, workspace_id, runtime_catalog, expert_registry
            )

    def apply_review_closure(
        self,
        verified: Any,
        *,
        authority: Any,
        authorization_token: bytes,
        mission_store_id: str,
        runtime_catalog: RuntimePackCatalog,
        expert_registry: ExpertRegistry,
        applied_at: int,
    ) -> ExpertWorkspaceClosureApplication:
        from .authenticated_expert_review import SQLiteAuthenticatedExpertReviewCustody

        if (
            type(authority) is not SQLiteAuthenticatedExpertReviewCustody
            or not authority.consume_workspace_projection_authorization(
                authorization_token,
                verified,
                "closure",
            )
            or verified.mission_store_id != mission_store_id
        ):
            raise StoreError("A valid local authenticated closure proof is required")
        return self._apply_review_closure_records(
            verified.records,
            mission_store_id=mission_store_id,
            runtime_catalog=runtime_catalog,
            expert_registry=expert_registry,
            applied_at=applied_at,
        )

    def _apply_review_closure_records(
        self,
        records: ExpertReviewRecordSet,
        *,
        mission_store_id: str,
        runtime_catalog: RuntimePackCatalog,
        expert_registry: ExpertRegistry,
        applied_at: int,
    ) -> ExpertWorkspaceClosureApplication:
        verified = verify_expert_review_record_set(records, expert_registry)
        mission_store_id = _identifier(mission_store_id, "mission_store_id")
        applied_at = _integer(applied_at, "applied_at", 0, 2**63 - 1)
        snapshot = verified.snapshot
        snapshot_document = snapshot.to_dict()
        closure_document = verified.closure.to_dict()
        if applied_at < closure_document["closed_at"]:
            raise StoreConflictError("Workspace closure application predates the closure")
        workspace_id = snapshot_document["workspace_id"]
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._verify_identity(connection)
                existing = connection.execute(
                    "SELECT * FROM workspace_review_closure_imports WHERE workspace_id = ?",
                    (workspace_id,),
                ).fetchone()
                if existing is not None:
                    durable_snapshot, durable_closure, durable_application = (
                        _validated_review_import_row(existing, expert_registry)
                    )
                    _validate_review_projection_event(
                        connection,
                        existing,
                        event_type="review_closure_applied",
                        payload={
                            "snapshot_id": durable_snapshot.snapshot_id,
                            "snapshot_sha256": durable_snapshot.snapshot_sha256,
                            "closure_id": durable_closure.closure_id,
                            "closure_sha256": durable_closure.closure_sha256,
                            "disposition": durable_closure.to_dict()["disposition"],
                            "application_id": durable_application.application_id,
                            "application_sha256": durable_application.application_sha256,
                        },
                    )
                    _validated_review_projection_tail(connection, existing, durable_closure)
                    if (
                        existing["snapshot_json"] == snapshot.document_json
                        and existing["closure_json"] == verified.closure.document_json
                        and existing["mission_store_id"] == mission_store_id
                    ):
                        return durable_application
                    raise StoreConflictError("Workspace closure conflicts with existing projection")
                current = self._review_snapshot_from_connection(
                    connection, workspace_id, runtime_catalog, expert_registry
                )
                if current != snapshot:
                    raise StoreConflictError("Workspace review snapshot is stale or substituted")
                workspace = connection.execute(
                    "SELECT revision FROM expert_workspaces WHERE workspace_id = ?",
                    (workspace_id,),
                ).fetchone()
                revision_before = _stored_integer(
                    workspace["revision"], "workspace revision", 0, 2**63 - 2
                )
                last_time = _stored_integer(
                    connection.execute(
                        "SELECT occurred_at FROM workspace_events WHERE workspace_id = ? "
                        "ORDER BY sequence_number DESC LIMIT 1",
                        (workspace_id,),
                    ).fetchone()[0],
                    "event occurrence time",
                    0,
                    2**63 - 1,
                )
                if applied_at < last_time:
                    raise StoreConflictError("Workspace event clock cannot move backward")
                application = build_expert_workspace_closure_application(
                    mission_store_id=mission_store_id,
                    workspace_id=workspace_id,
                    snapshot=snapshot,
                    closure=verified.closure,
                    workspace_revision_before=revision_before,
                    event_head_before_sha256=snapshot_document["event_head_sha256"],
                    applied_at=applied_at,
                )
                revision = revision_before + 1
                connection.execute(
                    "INSERT INTO workspace_review_closure_imports VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        verified.closure.closure_id,
                        verified.closure.closure_sha256,
                        snapshot.snapshot_id,
                        snapshot.snapshot_sha256,
                        workspace_id,
                        mission_store_id,
                        closure_document["disposition"],
                        snapshot.document_json,
                        verified.closure.document_json,
                        application.application_id,
                        application.application_sha256,
                        application.document_json,
                        applied_at,
                        revision,
                    ),
                )
                connection.execute(
                    "UPDATE expert_workspaces SET revision = ? WHERE workspace_id = ?",
                    (revision, workspace_id),
                )
                self._append_event(
                    connection,
                    workspace_id=workspace_id,
                    event_type="review_closure_applied",
                    revision=revision,
                    occurred_at=applied_at,
                    payload={
                        "snapshot_id": snapshot.snapshot_id,
                        "snapshot_sha256": snapshot.snapshot_sha256,
                        "closure_id": verified.closure.closure_id,
                        "closure_sha256": verified.closure.closure_sha256,
                        "disposition": closure_document["disposition"],
                        "application_id": application.application_id,
                        "application_sha256": application.application_sha256,
                    },
                )
                connection.commit()
                return application
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise StoreConflictError("Workspace closure replay was rejected") from exc
            except (sqlite3.Error, StoreError):
                connection.rollback()
                raise

    def apply_review_closure_revocation(
        self,
        verified: Any,
        *,
        authority: Any,
        authorization_token: bytes,
        runtime_catalog: RuntimePackCatalog,
        expert_registry: ExpertRegistry,
        applied_at: int,
    ) -> ExpertReviewClosureRevocation:
        from .authenticated_expert_review import SQLiteAuthenticatedExpertReviewCustody

        if (
            type(authority) is not SQLiteAuthenticatedExpertReviewCustody
            or not authority.consume_workspace_projection_authorization(
                authorization_token,
                verified,
                "revocation",
            )
        ):
            raise StoreError("A valid local authenticated revocation proof is required")
        return self._apply_review_closure_revocation_records(
            verified.records,
            runtime_catalog=runtime_catalog,
            expert_registry=expert_registry,
            applied_at=applied_at,
        )

    def _apply_review_closure_revocation_records(
        self,
        records: ExpertReviewRecordSet,
        *,
        runtime_catalog: RuntimePackCatalog,
        expert_registry: ExpertRegistry,
        applied_at: int,
    ) -> ExpertReviewClosureRevocation:
        verified = verify_expert_review_record_set(records, expert_registry)
        if verified.revocation is None:
            raise StoreError("Expert review record set has no closure revocation")
        applied_at = _integer(applied_at, "applied_at", 0, 2**63 - 1)
        if applied_at < verified.revocation.to_dict()["revoked_at"]:
            raise StoreConflictError("Workspace revocation application predates the revocation")
        workspace_id = verified.snapshot.to_dict()["workspace_id"]
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._verify_identity(connection)
                closure = connection.execute(
                    "SELECT * FROM workspace_review_closure_imports WHERE workspace_id = ?",
                    (workspace_id,),
                ).fetchone()
                if (
                    closure is None
                    or closure["closure_id"] != verified.closure.closure_id
                    or closure["closure_sha256"] != verified.closure.closure_sha256
                ):
                    raise StoreConflictError("Workspace closure is absent or substituted")
                durable_snapshot, durable_closure, durable_application = (
                    _validated_review_import_row(closure, expert_registry)
                )
                _validate_review_projection_event(
                    connection,
                    closure,
                    event_type="review_closure_applied",
                    payload={
                        "snapshot_id": durable_snapshot.snapshot_id,
                        "snapshot_sha256": durable_snapshot.snapshot_sha256,
                        "closure_id": durable_closure.closure_id,
                        "closure_sha256": durable_closure.closure_sha256,
                        "disposition": durable_closure.to_dict()["disposition"],
                        "application_id": durable_application.application_id,
                        "application_sha256": durable_application.application_sha256,
                    },
                )
                existing, durable_revocation = _validated_review_projection_tail(
                    connection, closure, durable_closure
                )
                if existing is not None:
                    if durable_revocation is None:
                        raise StoreIntegrityError(
                            "Workspace review projection tail is inconsistent"
                        )
                    if existing["revocation_json"] == verified.revocation.document_json:
                        return durable_revocation
                    raise StoreConflictError(
                        "Workspace revocation conflicts with existing projection"
                    )
                revision_before = _stored_integer(
                    connection.execute(
                        "SELECT revision FROM expert_workspaces WHERE workspace_id = ?",
                        (workspace_id,),
                    ).fetchone()[0],
                    "workspace revision",
                    0,
                    2**63 - 2,
                )
                last_time = _stored_integer(
                    connection.execute(
                        "SELECT occurred_at FROM workspace_events WHERE workspace_id = ? "
                        "ORDER BY sequence_number DESC LIMIT 1",
                        (workspace_id,),
                    ).fetchone()[0],
                    "event occurrence time",
                    0,
                    2**63 - 1,
                )
                if applied_at < last_time:
                    raise StoreConflictError("Workspace event clock cannot move backward")
                revision = revision_before + 1
                connection.execute(
                    "INSERT INTO workspace_review_closure_revocations VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        verified.revocation.revocation_id,
                        verified.revocation.revocation_sha256,
                        verified.closure.closure_id,
                        verified.closure.closure_sha256,
                        workspace_id,
                        verified.revocation.document_json,
                        applied_at,
                        revision,
                    ),
                )
                connection.execute(
                    "UPDATE expert_workspaces SET revision = ? WHERE workspace_id = ?",
                    (revision, workspace_id),
                )
                self._append_event(
                    connection,
                    workspace_id=workspace_id,
                    event_type="review_closure_revoked",
                    revision=revision,
                    occurred_at=applied_at,
                    payload={
                        "closure_id": verified.closure.closure_id,
                        "closure_sha256": verified.closure.closure_sha256,
                        "revocation_id": verified.revocation.revocation_id,
                        "revocation_sha256": verified.revocation.revocation_sha256,
                    },
                )
                connection.commit()
                return verified.revocation
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise StoreConflictError("Workspace revocation replay was rejected") from exc
            except (sqlite3.Error, StoreError):
                connection.rollback()
                raise

    def reconcile_review_records(
        self,
        records: ExpertReviewRecordSet,
        *,
        expert_registry: ExpertRegistry,
    ) -> ExpertReviewReconciliationReport:
        verified = verify_expert_review_record_set(records, expert_registry)
        workspace_id = verified.snapshot.to_dict()["workspace_id"]
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            self._verify_identity(connection)
            closure = connection.execute(
                "SELECT * FROM workspace_review_closure_imports WHERE workspace_id = ?",
                (workspace_id,),
            ).fetchone()
            revocation = connection.execute(
                "SELECT * FROM workspace_review_closure_revocations WHERE workspace_id = ?",
                (workspace_id,),
            ).fetchone()
            if closure is None:
                status = ReconciliationStatus.CLOSURE_PENDING_WORKSPACE_APPLICATION
                application_id = None
            else:
                local_snapshot, local_closure, local_application = _validated_review_import_row(
                    closure, expert_registry
                )
                _validate_review_projection_event(
                    connection,
                    closure,
                    event_type="review_closure_applied",
                    payload={
                        "snapshot_id": local_snapshot.snapshot_id,
                        "snapshot_sha256": local_snapshot.snapshot_sha256,
                        "closure_id": local_closure.closure_id,
                        "closure_sha256": local_closure.closure_sha256,
                        "disposition": local_closure.to_dict()["disposition"],
                        "application_id": local_application.application_id,
                        "application_sha256": local_application.application_sha256,
                    },
                )
                application_id = closure["application_id"]
                local_revocation_row, local_revocation = _validated_review_projection_tail(
                    connection, closure, local_closure
                )
                if (revocation is None) != (local_revocation_row is None):
                    raise StoreIntegrityError("Workspace review projection tail is inconsistent")
                if local_snapshot.snapshot_sha256 != verified.snapshot.snapshot_sha256:
                    status = ReconciliationStatus.SNAPSHOT_MISMATCH
                elif local_closure.closure_sha256 != verified.closure.closure_sha256:
                    status = ReconciliationStatus.CERTIFICATE_MISMATCH
                elif local_application.to_dict()["mission_store_id"] != closure["mission_store_id"]:
                    raise StoreIntegrityError(
                        "Stored workspace closure mission-store binding is inconsistent"
                    )
                elif verified.revocation is not None and local_revocation is None:
                    status = ReconciliationStatus.REVOCATION_PENDING_WORKSPACE_APPLICATION
                elif verified.revocation is None and local_revocation is not None:
                    status = ReconciliationStatus.WORKSPACE_PROJECTION_MISSING_MISSION_RECORD
                elif (
                    local_revocation is not None
                    and verified.revocation is not None
                    and local_revocation.revocation_sha256 != verified.revocation.revocation_sha256
                ):
                    status = ReconciliationStatus.CERTIFICATE_MISMATCH
                else:
                    status = ReconciliationStatus.CONSISTENT
            return ExpertReviewReconciliationReport(
                status=status,
                workspace_id=workspace_id,
                snapshot_id=verified.snapshot.snapshot_id,
                snapshot_sha256=verified.snapshot.snapshot_sha256,
                closure_id=verified.closure.closure_id,
                closure_sha256=verified.closure.closure_sha256,
                local_application_id=application_id,
                revocation_id=(
                    None if verified.revocation is None else verified.revocation.revocation_id
                ),
                local_revocation_id=(None if revocation is None else revocation["revocation_id"]),
            )

    def verify_store(
        self,
        runtime_catalog: RuntimePackCatalog,
        *,
        expert_registry: ExpertRegistry | None = None,
    ) -> ExpertWorkspaceVerificationReport:
        _catalog_document(runtime_catalog)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            self._verify_identity(connection)
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
            if integrity != "ok" or foreign_keys:
                raise StoreIntegrityError("Expert workspace SQLite integrity check failed")
            workspaces = connection.execute(
                "SELECT * FROM expert_workspaces ORDER BY workspace_id"
            ).fetchall()
            summary: list[dict[str, Any]] = []
            for workspace in workspaces:
                definition = _validated_workspace_row(workspace, runtime_catalog)
                definition_document = definition.to_dict()
                assignments = connection.execute(
                    "SELECT * FROM workspace_assignments WHERE workspace_id = ? ORDER BY work_id",
                    (definition.workspace_id,),
                ).fetchall()
                for item in assignments:
                    _validated_assignment_row(item, definition)
                normalized_assignments = [
                    {
                        "work_id": item["work_id"],
                        "profile_id": item["profile_id"],
                        "command_id": item["command_id"],
                        "runtime_pack_id": item["runtime_pack_id"],
                        "runtime_pack_sha256": item["runtime_pack_sha256"],
                        "maximum_attempts": _stored_integer(
                            item["maximum_attempts"],
                            "assignment maximum_attempts",
                            1,
                            MAX_ATTEMPTS_PER_WORK,
                        ),
                    }
                    for item in assignments
                ]
                if normalized_assignments != definition_document["assignments"]:
                    raise StoreIntegrityError("Stored assignments do not match the definition")
                dependency_rows = connection.execute(
                    "SELECT work_id, depends_on_work_id FROM workspace_dependencies "
                    "WHERE workspace_id = ? ORDER BY work_id, depends_on_work_id",
                    (definition.workspace_id,),
                ).fetchall()
                if (
                    any(
                        type(item["work_id"]) is not str
                        or type(item["depends_on_work_id"]) is not str
                        for item in dependency_rows
                    )
                    or [dict(item) for item in dependency_rows]
                    != definition_document["dependencies"]
                ):
                    raise StoreIntegrityError("Stored dependencies do not match the definition")
                review_rows = connection.execute(
                    "SELECT * FROM workspace_review_requirements WHERE workspace_id = ? "
                    "ORDER BY work_id",
                    (definition.workspace_id,),
                ).fetchall()
                normalized_reviews = [
                    {
                        "work_id": item["work_id"],
                        "required": bool(
                            _stored_integer(item["required"], "review required flag", 0, 1)
                        ),
                        "reviewer_profile_ids": _load_canonical_stored_json(
                            item["reviewer_profile_ids_json"], "reviewer profile IDs"
                        ),
                        "producer_excluded": bool(
                            _stored_integer(
                                item["producer_excluded"],
                                "producer exclusion flag",
                                1,
                                1,
                            )
                        ),
                    }
                    for item in review_rows
                ]
                if any(
                    type(item["work_id"]) is not str
                    or type(item["workspace_id"]) is not str
                    or item["workspace_id"] != definition.workspace_id
                    for item in review_rows
                ):
                    raise StoreIntegrityError("Stored review identity is invalid")
                if normalized_reviews != definition_document["review_requirements"]:
                    raise StoreIntegrityError("Stored reviews do not match the definition")
                events = connection.execute(
                    "SELECT * FROM workspace_events WHERE workspace_id = ? "
                    "ORDER BY sequence_number",
                    (definition.workspace_id,),
                ).fetchall()
                previous = None
                previous_time: int | None = None
                event_lease_ids: set[str] = set()
                event_product_ids: set[str] = set()
                product_event_indexes = [
                    index
                    for index, item in enumerate(events)
                    if item["event_type"] == "work_product_accepted"
                ]
                last_product_event_index = (
                    None if not product_event_indexes else product_event_indexes[-1]
                )
                closure_event_ids: set[str] = set()
                revocation_event_ids: set[str] = set()
                for index, event in enumerate(events):
                    sequence_number = _stored_integer(
                        event["sequence_number"], "event sequence_number", 0, 2**63 - 1
                    )
                    workspace_revision = _stored_integer(
                        event["workspace_revision"], "event workspace revision", 0, 2**63 - 1
                    )
                    occurred_at = _stored_integer(
                        event["occurred_at"], "event occurrence time", 0, 2**63 - 1
                    )
                    payload = _load_canonical_stored_json(event["payload_json"], "event payload")
                    checked_event = _event_document(
                        definition.workspace_id,
                        index,
                        previous,
                        _stored_text(event["event_type"], "event type"),
                        workspace_revision,
                        occurred_at,
                        payload,
                    )
                    if (
                        type(event["workspace_id"]) is not str
                        or event["workspace_id"] != definition.workspace_id
                        or sequence_number != index
                        or event["previous_event_sha256"] != previous
                        or event["event_id"] != checked_event["event_id"]
                        or event["event_sha256"] != checked_event["event_sha256"]
                        or workspace_revision != index
                    ):
                        raise StoreIntegrityError("Workspace event chain is invalid")
                    if previous_time is not None and occurred_at < previous_time:
                        raise StoreIntegrityError("Workspace event clock moved backward")
                    event_type = _stored_text(event["event_type"], "event type")
                    if event_type == "workspace_created":
                        if (
                            index != 0
                            or occurred_at
                            != _stored_integer(
                                workspace["created_at"],
                                "workspace creation time",
                                0,
                                2**63 - 1,
                            )
                            or payload != {"workspace_sha256": definition.workspace_sha256}
                        ):
                            raise StoreIntegrityError("Workspace creation event is invalid")
                    elif event_type == "lease_acquired":
                        lease = connection.execute(
                            "SELECT * FROM workspace_leases WHERE lease_id = ? "
                            "AND workspace_id = ?",
                            (payload.get("lease_id"), definition.workspace_id),
                        ).fetchone()
                        if (
                            lease is None
                            or payload
                            != {
                                "lease_id": lease["lease_id"],
                                "work_id": lease["work_id"],
                                "attempt_number": _stored_integer(
                                    lease["attempt_number"],
                                    "lease attempt_number",
                                    1,
                                    MAX_ATTEMPTS_PER_WORK,
                                ),
                                "fencing_token": _stored_integer(
                                    lease["fencing_token"],
                                    "lease fencing_token",
                                    1,
                                    MAX_ATTEMPTS_PER_WORK,
                                ),
                                "envelope_id": lease["envelope_id"],
                            }
                            or occurred_at
                            != _stored_integer(
                                lease["acquired_at"], "lease acquisition time", 0, 2**63 - 1
                            )
                        ):
                            raise StoreIntegrityError("Workspace lease event is invalid")
                        lease_id = _stored_text(lease["lease_id"], "lease_id")
                        if lease_id in event_lease_ids:
                            raise StoreIntegrityError("Workspace lease event is duplicated")
                        event_lease_ids.add(lease_id)
                    elif event_type == "work_product_accepted":
                        product = connection.execute(
                            "SELECT p.*, l.fencing_token FROM workspace_products p "
                            "JOIN workspace_leases l ON l.lease_id = p.lease_id "
                            "WHERE p.product_id = ? AND p.workspace_id = ?",
                            (payload.get("product_id"), definition.workspace_id),
                        ).fetchone()
                        if (
                            product is None
                            or payload
                            != {
                                "lease_id": product["lease_id"],
                                "work_id": product["work_id"],
                                "attempt_number": _stored_integer(
                                    product["attempt_number"],
                                    "product attempt_number",
                                    1,
                                    MAX_ATTEMPTS_PER_WORK,
                                ),
                                "fencing_token": _stored_integer(
                                    product["fencing_token"],
                                    "lease fencing_token",
                                    1,
                                    MAX_ATTEMPTS_PER_WORK,
                                ),
                                "product_id": product["product_id"],
                                "product_sha256": product["product_sha256"],
                                "product_type": product["product_type"],
                                "workspace_status": (
                                    _stored_text(workspace["status"], "workspace status")
                                    if index == last_product_event_index
                                    and workspace["status"] != "active"
                                    else "active"
                                ),
                            }
                            or occurred_at
                            != _stored_integer(
                                product["accepted_at"],
                                "product acceptance time",
                                0,
                                2**63 - 1,
                            )
                        ):
                            raise StoreIntegrityError("Workspace product event is invalid")
                        product_id = _stored_text(product["product_id"], "product_id")
                        if product_id in event_product_ids:
                            raise StoreIntegrityError("Workspace product event is duplicated")
                        event_product_ids.add(product_id)
                    elif event_type == "review_closure_applied":
                        closure_row = connection.execute(
                            "SELECT * FROM workspace_review_closure_imports "
                            "WHERE closure_id = ? AND workspace_id = ?",
                            (payload.get("closure_id"), definition.workspace_id),
                        ).fetchone()
                        if closure_row is None or expert_registry is None:
                            raise StoreIntegrityError(
                                "Workspace closure event lacks a verifiable import"
                            )
                        snapshot, closure, application = _validated_review_import_row(
                            closure_row, expert_registry
                        )
                        application_document = application.to_dict()
                        closure_document = closure.to_dict()
                        snapshot_document = snapshot.to_dict()
                        snapshot_products = {
                            item["product_id"]: item for item in snapshot_document["products"]
                        }
                        stored_products = connection.execute(
                            "SELECT product_id, product_sha256, work_id, producer_profile_id, "
                            "command_id, product_type, envelope_id, attempt_number "
                            "FROM workspace_products WHERE workspace_id = ?",
                            (definition.workspace_id,),
                        ).fetchall()
                        if set(snapshot_products) != {
                            item["product_id"] for item in stored_products
                        }:
                            raise StoreIntegrityError(
                                "Workspace closure snapshot product inventory is invalid"
                            )
                        for stored_product in stored_products:
                            snapshot_product = snapshot_products[stored_product["product_id"]]
                            for field in (
                                "product_sha256",
                                "work_id",
                                "producer_profile_id",
                                "command_id",
                                "product_type",
                                "envelope_id",
                            ):
                                if snapshot_product[field] != stored_product[field]:
                                    raise StoreIntegrityError(
                                        "Workspace closure snapshot product binding is invalid"
                                    )
                            if snapshot_product["attempt_number"] != _stored_integer(
                                stored_product["attempt_number"],
                                "snapshot product attempt number",
                                1,
                                MAX_ATTEMPTS_PER_WORK,
                            ):
                                raise StoreIntegrityError(
                                    "Workspace closure snapshot attempt is invalid"
                                )
                        expected_payload = {
                            "snapshot_id": snapshot.snapshot_id,
                            "snapshot_sha256": snapshot.snapshot_sha256,
                            "closure_id": closure.closure_id,
                            "closure_sha256": closure.closure_sha256,
                            "disposition": closure_document["disposition"],
                            "application_id": application.application_id,
                            "application_sha256": application.application_sha256,
                        }
                        stored_revision = _stored_integer(
                            closure_row["workspace_revision"],
                            "closure workspace revision",
                            1,
                            2**63 - 1,
                        )
                        if (
                            payload != expected_payload
                            or occurred_at
                            != _stored_integer(
                                closure_row["applied_at"],
                                "closure application time",
                                0,
                                2**63 - 1,
                            )
                            or stored_revision != workspace_revision
                            or closure_row["closure_sha256"] != closure.closure_sha256
                            or closure_row["closure_id"] != closure.closure_id
                            or closure_row["snapshot_sha256"] != snapshot.snapshot_sha256
                            or closure_row["snapshot_id"] != snapshot.snapshot_id
                            or closure_row["application_sha256"] != application.application_sha256
                            or closure_row["application_id"] != application.application_id
                            or closure_row["workspace_id"] != definition.workspace_id
                            or closure_row["disposition"] != closure_document["disposition"]
                            or snapshot_document["workspace_id"] != definition.workspace_id
                            or snapshot_document["workspace_sha256"] != definition.workspace_sha256
                            or snapshot_document["tenant_id"] != definition.tenant_id
                            or snapshot_document["mission_id"] != definition.mission_id
                            or snapshot_document["plan_id"] != definition.plan_id
                            or snapshot_document["runtime_catalog_sha256"]
                            != definition.runtime_catalog_sha256
                            or snapshot_document["target_scope_sha256"]
                            != definition.target_scope_sha256
                            or snapshot_document["authority_snapshot_sha256"]
                            != definition.authority_snapshot_sha256
                            or snapshot_document["evidence_snapshot_sha256"]
                            != definition.evidence_snapshot_sha256
                            or snapshot_document["workspace_schema_version"]
                            not in {2, SCHEMA_VERSION}
                            or snapshot_document["workspace_revision"] != stored_revision - 1
                            or snapshot_document["event_count"] != index
                            or snapshot_document["event_head_sha256"] != previous
                            or snapshot_document["event_head_occurred_at"] != previous_time
                            or application_document["workspace_revision_after"] != stored_revision
                            or application_document["workspace_revision_before"]
                            != stored_revision - 1
                            or application_document["mission_store_id"]
                            != closure_row["mission_store_id"]
                            or application_document["snapshot_id"] != snapshot.snapshot_id
                            or application_document["snapshot_sha256"] != snapshot.snapshot_sha256
                            or application_document["closure_id"] != closure.closure_id
                            or application_document["closure_sha256"] != closure.closure_sha256
                            or application_document["event_head_before_sha256"] != previous
                        ):
                            raise StoreIntegrityError(
                                "Workspace closure projection is inconsistent"
                            )
                        if closure.closure_id in closure_event_ids:
                            raise StoreIntegrityError("Workspace closure event is duplicated")
                        closure_event_ids.add(closure.closure_id)
                    elif event_type == "review_closure_revoked":
                        revocation_row = connection.execute(
                            "SELECT * FROM workspace_review_closure_revocations "
                            "WHERE revocation_id = ? AND workspace_id = ?",
                            (payload.get("revocation_id"), definition.workspace_id),
                        ).fetchone()
                        if revocation_row is None:
                            raise StoreIntegrityError("Workspace revocation event lacks an import")
                        closure_row = connection.execute(
                            "SELECT * FROM workspace_review_closure_imports "
                            "WHERE closure_id = ? AND workspace_id = ?",
                            (revocation_row["closure_id"], definition.workspace_id),
                        ).fetchone()
                        if closure_row is None or expert_registry is None:
                            raise StoreIntegrityError(
                                "Workspace revocation lacks a verifiable closure"
                            )
                        _, durable_closure, _ = _validated_review_import_row(
                            closure_row, expert_registry
                        )
                        revocation = _validated_review_revocation_row(
                            revocation_row, durable_closure, definition.workspace_id
                        )
                        expected_payload = {
                            "closure_id": revocation.to_dict()["closure_id"],
                            "closure_sha256": revocation.to_dict()["closure_sha256"],
                            "revocation_id": revocation.revocation_id,
                            "revocation_sha256": revocation.revocation_sha256,
                        }
                        stored_revision = _stored_integer(
                            revocation_row["workspace_revision"],
                            "revocation workspace revision",
                            1,
                            2**63 - 1,
                        )
                        if (
                            payload != expected_payload
                            or occurred_at
                            != _stored_integer(
                                revocation_row["applied_at"],
                                "revocation application time",
                                0,
                                2**63 - 1,
                            )
                            or stored_revision != workspace_revision
                            or revocation_row["revocation_sha256"] != revocation.revocation_sha256
                            or revocation_row["closure_id"] != revocation.to_dict()["closure_id"]
                            or revocation_row["closure_sha256"]
                            != revocation.to_dict()["closure_sha256"]
                            or stored_revision
                            != _stored_integer(
                                closure_row["workspace_revision"],
                                "closure workspace revision",
                                1,
                                2**63 - 2,
                            )
                            + 1
                        ):
                            raise StoreIntegrityError(
                                "Workspace revocation projection is inconsistent"
                            )
                        if revocation.revocation_id in revocation_event_ids:
                            raise StoreIntegrityError("Workspace revocation event is duplicated")
                        revocation_event_ids.add(revocation.revocation_id)
                    else:
                        raise StoreIntegrityError("Workspace event type is invalid")
                    previous = _stored_text(event["event_sha256"], "event SHA-256")
                    previous_time = occurred_at
                if (
                    not events
                    or _stored_integer(workspace["revision"], "workspace revision", 0, 2**63 - 1)
                    != len(events) - 1
                ):
                    raise StoreIntegrityError("Workspace revision does not match its event chain")
                cache: dict[str, WorkProduct] = {}
                products = connection.execute(
                    "SELECT * FROM workspace_products WHERE workspace_id = ? ORDER BY product_id",
                    (definition.workspace_id,),
                ).fetchall()
                for product in products:
                    parsed_product = self._parsed_stored_product(
                        connection,
                        _stored_text(product["product_id"], "product_id"),
                        runtime_catalog,
                        cache,
                        set(),
                    )
                    lineage = {
                        _stored_text(item["child_product_id"], "child product_id")
                        for item in connection.execute(
                            "SELECT child_product_id FROM workspace_product_lineage "
                            "WHERE workspace_id = ? AND product_id = ?",
                            (definition.workspace_id, product["product_id"]),
                        ).fetchall()
                    }
                    dependency_products = {
                        _stored_text(item["terminal_product_id"], "dependency terminal product_id")
                        for item in connection.execute(
                            "SELECT a.terminal_product_id FROM workspace_dependencies d "
                            "JOIN workspace_assignments a ON a.workspace_id = d.workspace_id "
                            "AND a.work_id = d.depends_on_work_id "
                            "WHERE d.workspace_id = ? AND d.work_id = ?",
                            (definition.workspace_id, product["work_id"]),
                        ).fetchall()
                        if item["terminal_product_id"] is not None
                    }
                    if parsed_product.product_type == "commander_synthesis":
                        if lineage != dependency_products:
                            raise StoreIntegrityError(
                                "Stored commander synthesis lineage is incomplete"
                            )
                        expected_disagreements = parsed_product.to_dict()["payload"][
                            "disagreements"
                        ]
                    else:
                        if lineage:
                            raise StoreIntegrityError(
                                "Stored specialist product has synthesis lineage"
                            )
                        expected_disagreements = []
                    disagreement_rows = connection.execute(
                        "SELECT disagreement_index, disagreement_json "
                        "FROM workspace_disagreements "
                        "WHERE workspace_id = ? AND synthesis_product_id = ? "
                        "ORDER BY disagreement_index",
                        (definition.workspace_id, product["product_id"]),
                    ).fetchall()
                    if any(
                        _stored_integer(
                            item["disagreement_index"],
                            "disagreement index",
                            0,
                            MAX_DEPENDENCIES - 1,
                        )
                        != index
                        for index, item in enumerate(disagreement_rows)
                    ):
                        raise StoreIntegrityError("Stored disagreement sequence is invalid")
                    actual_disagreements = [
                        _load_canonical_stored_json(
                            item["disagreement_json"], "commander disagreement"
                        )
                        for item in disagreement_rows
                    ]
                    if actual_disagreements != expected_disagreements:
                        raise StoreIntegrityError("Stored disagreement records are invalid")
                if event_product_ids != {
                    _stored_text(item["product_id"], "product_id") for item in products
                }:
                    raise StoreIntegrityError("Workspace product events are incomplete")
                completed = 0
                lease_count = 0
                for assignment in assignments:
                    leases = connection.execute(
                        "SELECT * FROM workspace_leases WHERE workspace_id = ? AND work_id = ? "
                        "ORDER BY attempt_number",
                        (definition.workspace_id, assignment["work_id"]),
                    ).fetchall()
                    lease_count += len(leases)
                    previous_expiry: int | None = None
                    for index, lease in enumerate(leases, start=1):
                        pack = _pack_for_profile(
                            runtime_catalog,
                            _stored_text(assignment["profile_id"], "assignment profile_id"),
                        )
                        raw_envelope = _load_canonical_stored_json(
                            lease["envelope_json"],
                            "execution envelope",
                            maximum_bytes=MAX_EXECUTION_ENVELOPE_BYTES,
                        )
                        envelope = parse_execution_envelope(raw_envelope, pack, runtime_catalog)
                        if (
                            type(lease["workspace_id"]) is not str
                            or lease["workspace_id"] != definition.workspace_id
                            or type(lease["work_id"]) is not str
                            or lease["work_id"] != assignment["work_id"]
                            or _stored_integer(
                                lease["attempt_number"],
                                "lease attempt_number",
                                1,
                                MAX_ATTEMPTS_PER_WORK,
                            )
                            != index
                            or _stored_integer(
                                lease["fencing_token"],
                                "lease fencing_token",
                                1,
                                MAX_ATTEMPTS_PER_WORK,
                            )
                            != index
                            or envelope.envelope_id != lease["envelope_id"]
                            or envelope.envelope_sha256 != lease["envelope_sha256"]
                            or envelope.work_id != assignment["work_id"]
                            or envelope.mission_id != definition.mission_id
                            or envelope.plan_id != definition.plan_id
                            or envelope.target_scope_sha256 != definition.target_scope_sha256
                            or envelope.authority_snapshot_sha256
                            != definition.authority_snapshot_sha256
                            or envelope.evidence_snapshot_sha256
                            != definition.evidence_snapshot_sha256
                        ):
                            raise StoreIntegrityError("Workspace lease sequence is invalid")
                        acquired_at = _stored_integer(
                            lease["acquired_at"], "lease acquisition time", 0, 2**63 - 1
                        )
                        expires_at = _stored_integer(
                            lease["expires_at"], "lease expiry time", 1, 2**63 - 1
                        )
                        lease_body = {
                            "workspace_id": definition.workspace_id,
                            "work_id": assignment["work_id"],
                            "attempt_number": index,
                            "fencing_token": index,
                            "envelope_id": envelope.envelope_id,
                            "envelope_sha256": envelope.envelope_sha256,
                            "acquired_at": acquired_at,
                            "expires_at": expires_at,
                        }
                        lease_digest = _canonical_sha256(
                            {"domain": LEASE_DOMAIN, "lease": lease_body}
                        )
                        if (
                            lease["lease_id"]
                            != f"EWL-{lease_digest.removeprefix('sha256:')[:32].upper()}"
                            or acquired_at
                            < _stored_integer(
                                workspace["created_at"],
                                "workspace creation time",
                                0,
                                2**63 - 1,
                            )
                            or expires_at <= acquired_at
                            or expires_at - acquired_at > MAX_LEASE_SECONDS
                            or (previous_expiry is not None and acquired_at < previous_expiry)
                        ):
                            raise StoreIntegrityError("Workspace lease identity or time is invalid")
                        previous_expiry = expires_at
                    if {
                        _stored_text(item["lease_id"], "lease_id") for item in leases
                    } - event_lease_ids:
                        raise StoreIntegrityError("Workspace lease events are incomplete")
                    terminal_id = assignment["terminal_product_id"]
                    if assignment["status"] == "completed":
                        completed += 1
                        if (
                            terminal_id not in cache
                            or not leases
                            or leases[-1]["status"] != "completed"
                        ):
                            raise StoreIntegrityError(
                                "Completed assignment terminal state is invalid"
                            )
                    elif terminal_id is not None:
                        raise StoreIntegrityError("Nonterminal assignment has a terminal product")
                    if leases:
                        prior_statuses = [
                            _stored_text(item["status"], "lease status") for item in leases[:-1]
                        ]
                        if any(status != "expired" for status in prior_statuses):
                            raise StoreIntegrityError("Superseded lease state is invalid")
                        expected_lease_status = {
                            "leased": "active",
                            "completed": "completed",
                        }.get(_stored_text(assignment["status"], "assignment status"))
                        if (
                            expected_lease_status is None
                            or leases[-1]["status"] != expected_lease_status
                        ):
                            raise StoreIntegrityError("Current lease state is invalid")
                    elif assignment["status"] != "pending":
                        raise StoreIntegrityError("Unleased assignment state is invalid")
                    if _stored_integer(
                        assignment["attempt_count"],
                        "assignment attempt_count",
                        0,
                        MAX_ATTEMPTS_PER_WORK,
                    ) != len(leases) or _stored_integer(
                        assignment["fencing_token"],
                        "assignment fencing_token",
                        0,
                        MAX_ATTEMPTS_PER_WORK,
                    ) != len(leases):
                        raise StoreIntegrityError("Assignment lease counters are invalid")
                review_required = any(
                    bool(_stored_integer(item["required"], "review required flag", 0, 1))
                    for item in review_rows
                )
                if completed != len(assignments):
                    expected_status = "active"
                elif review_required:
                    expected_status = "products_complete_pending_review"
                else:
                    expected_status = "completed"
                if workspace["status"] != expected_status:
                    raise StoreIntegrityError("Workspace terminal status is invalid")
                closure_rows = connection.execute(
                    "SELECT * FROM workspace_review_closure_imports WHERE workspace_id = ?",
                    (definition.workspace_id,),
                ).fetchall()
                if closure_rows:
                    if expert_registry is None or len(closure_rows) != 1:
                        raise StoreIntegrityError(
                            "Workspace closure source projection is unverifiable"
                        )
                    durable_snapshot, _, _ = _validated_review_import_row(
                        closure_rows[0], expert_registry
                    )
                    current_snapshot = self._review_snapshot_from_connection(
                        connection,
                        definition.workspace_id,
                        runtime_catalog,
                        expert_registry,
                    )
                    historical_document = durable_snapshot.to_dict()
                    current_document = current_snapshot.to_dict()
                    volatile_fields = {
                        "snapshot_id",
                        "snapshot_sha256",
                        "workspace_revision",
                        "event_count",
                        "event_head_sha256",
                        "event_head_occurred_at",
                    }
                    if {
                        key: value
                        for key, value in historical_document.items()
                        if key not in volatile_fields
                    } != {
                        key: value
                        for key, value in current_document.items()
                        if key not in volatile_fields
                    }:
                        raise StoreIntegrityError(
                            "Workspace closure source projection is inconsistent"
                        )
                stored_closure_ids = {
                    _stored_text(item["closure_id"], "closure ID")
                    for item in connection.execute(
                        "SELECT closure_id FROM workspace_review_closure_imports "
                        "WHERE workspace_id = ?",
                        (definition.workspace_id,),
                    ).fetchall()
                }
                stored_revocation_ids = {
                    _stored_text(item["revocation_id"], "revocation ID")
                    for item in connection.execute(
                        "SELECT revocation_id FROM workspace_review_closure_revocations "
                        "WHERE workspace_id = ?",
                        (definition.workspace_id,),
                    ).fetchall()
                }
                if (
                    stored_closure_ids != closure_event_ids
                    or stored_revocation_ids != revocation_event_ids
                    or len(events)
                    != 1
                    + len(event_lease_ids)
                    + len(event_product_ids)
                    + len(closure_event_ids)
                    + len(revocation_event_ids)
                ):
                    raise StoreIntegrityError("Workspace event inventory is invalid")
                summary.append(
                    {
                        "workspace_id": definition.workspace_id,
                        "workspace_sha256": definition.workspace_sha256,
                        "revision": _stored_integer(
                            workspace["revision"], "workspace revision", 0, 2**63 - 1
                        ),
                        "status": workspace["status"],
                        "assignment_count": len(assignments),
                        "lease_count": lease_count,
                        "product_ids": sorted(cache),
                        "closure_ids": sorted(stored_closure_ids),
                        "revocation_ids": sorted(stored_revocation_ids),
                        "event_head": previous,
                    }
                )
            counts = {
                "assignment_count": _stored_integer(
                    connection.execute("SELECT COUNT(*) FROM workspace_assignments").fetchone()[0],
                    "assignment count",
                    0,
                    2**63 - 1,
                ),
                "lease_count": _stored_integer(
                    connection.execute("SELECT COUNT(*) FROM workspace_leases").fetchone()[0],
                    "lease count",
                    0,
                    2**63 - 1,
                ),
                "product_count": _stored_integer(
                    connection.execute("SELECT COUNT(*) FROM workspace_products").fetchone()[0],
                    "product count",
                    0,
                    2**63 - 1,
                ),
                "event_count": _stored_integer(
                    connection.execute("SELECT COUNT(*) FROM workspace_events").fetchone()[0],
                    "event count",
                    0,
                    2**63 - 1,
                ),
                "closure_count": _stored_integer(
                    connection.execute(
                        "SELECT COUNT(*) FROM workspace_review_closure_imports"
                    ).fetchone()[0],
                    "closure count",
                    0,
                    2**63 - 1,
                ),
                "revocation_count": _stored_integer(
                    connection.execute(
                        "SELECT COUNT(*) FROM workspace_review_closure_revocations"
                    ).fetchone()[0],
                    "revocation count",
                    0,
                    2**63 - 1,
                ),
            }
            digest = _canonical_sha256(
                {
                    "domain": "sunderkey.expert-workspace-store-verification.v1",
                    "schema_version": SCHEMA_VERSION,
                    "runtime_catalog_sha256": runtime_catalog.catalog_sha256,
                    "workspaces": summary,
                    **counts,
                }
            )
            return ExpertWorkspaceVerificationReport(
                status="valid",
                schema_version=SCHEMA_VERSION,
                workspace_count=len(workspaces),
                assignment_count=counts["assignment_count"],
                lease_count=counts["lease_count"],
                product_count=counts["product_count"],
                event_count=counts["event_count"],
                store_sha256=digest,
            )


__all__ = [
    "APPLICATION_ID",
    "SCHEMA_VERSION",
    "ExpertWorkspaceAcceptanceReceipt",
    "ExpertWorkspaceDefinition",
    "ExpertWorkspaceLeaseReceipt",
    "ExpertWorkspaceState",
    "ExpertWorkspaceStoreAdapter",
    "ExpertWorkspaceVerificationReport",
    "SQLiteExpertWorkspaceStore",
    "build_expert_workspace_definition",
    "parse_expert_workspace_definition",
]
