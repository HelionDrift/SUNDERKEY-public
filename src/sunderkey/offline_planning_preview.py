"""Read-only tenant-bound preview of an archived offline API plan."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from .coverage_scheduler import CoverageSchedule
from .local_api_service import (
    AccessAuthorizer,
    AccessCheck,
    AccessContext,
    AccessDecision,
    DecisionStatus,
    LocalApiServiceError,
    canonical_sha256,
)
from .offline_api_planning_bundle import (
    OfflineApiPlanningError,
    inspect_offline_api_planning_integrity,
)
from .registry import ExpertRegistry

PREVIEW_DOMAIN = "sunderkey.offline-planning-preview.v1"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
NO_EFFECTS = {
    "execution": "none",
    "finding_publication": "none",
    "mutation": "none",
    "network": "none",
    "qualification": "none",
}


class OfflinePlanningPreviewError(ValueError):
    """Raised when read access, tenant binding, or archive integrity fails."""


@dataclass(frozen=True, slots=True)
class PlanningBundleRecord:
    tenant_id: str
    context_id: str
    bundle_sha256: str
    bundle: Mapping[str, Any]

    def __post_init__(self) -> None:
        for name in ("tenant_id", "context_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
                raise OfflinePlanningPreviewError(f"stored {name} is invalid")
        if (
            not isinstance(self.bundle_sha256, str)
            or SHA256_RE.fullmatch(self.bundle_sha256) is None
            or not isinstance(self.bundle, Mapping)
        ):
            raise OfflinePlanningPreviewError("stored planning bundle is invalid")


class PlanningBundleReader(Protocol):
    def get(
        self, tenant_id: str, context_id: str, bundle_sha256: str
    ) -> PlanningBundleRecord | None: ...


@dataclass(frozen=True, slots=True)
class PlanningPreviewRequest:
    request_id: str
    access: AccessContext
    requested_at: str
    bundle_sha256: str
    expected_scope_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or IDENTIFIER_RE.fullmatch(self.request_id) is None:
            raise OfflinePlanningPreviewError("preview request_id is invalid")
        if not isinstance(self.access, AccessContext):
            raise OfflinePlanningPreviewError("preview access context is invalid")
        if not isinstance(self.requested_at, str) or UTC_RE.fullmatch(self.requested_at) is None:
            raise OfflinePlanningPreviewError("preview requested_at is invalid")
        try:
            datetime.fromisoformat(self.requested_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise OfflinePlanningPreviewError("preview requested_at is invalid") from exc
        for name in ("bundle_sha256", "expected_scope_sha256"):
            value = getattr(self, name)
            if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
                raise OfflinePlanningPreviewError(f"preview {name} is invalid")

    @property
    def request_sha256(self) -> str:
        return canonical_sha256(
            {
                "operation": "preview_offline_plan",
                "request_id": self.request_id,
                "access": {
                    "tenant_id": self.access.tenant_id,
                    "context_id": self.access.context_id,
                    "principal_id": self.access.principal_id,
                    "session_ref": self.access.session_ref,
                },
                "requested_at": self.requested_at,
                "bundle_sha256": self.bundle_sha256,
                "expected_scope_sha256": self.expected_scope_sha256,
            }
        )


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


class OfflinePlanningPreviewService:
    """Authorize and inspect one tenant-scoped bundle without changing state."""

    def __init__(
        self,
        reader: PlanningBundleReader,
        authorizer: AccessAuthorizer,
        registry: ExpertRegistry,
    ) -> None:
        self._reader = reader
        self._authorizer = authorizer
        self._registry = registry

    def preview(self, request: PlanningPreviewRequest, *, as_of: str) -> dict[str, Any]:
        if not isinstance(request, PlanningPreviewRequest):
            raise OfflinePlanningPreviewError("typed preview request is required")
        if as_of != request.requested_at:
            raise OfflinePlanningPreviewError("preview requested_at differs from trusted clock")
        check = AccessCheck(
            request_sha256=request.request_sha256,
            tenant_id=request.access.tenant_id,
            context_id=request.access.context_id,
            principal_id=request.access.principal_id,
            session_ref=request.access.session_ref,
            permission="resource:read",
            requested_at=request.requested_at,
        )
        try:
            decision = self._authorizer.authorize(check)
            if (
                not isinstance(decision, AccessDecision)
                or decision.status is not DecisionStatus.ALLOWED
                or decision.request_sha256 != check.request_sha256
                or decision.tenant_id != check.tenant_id
                or decision.context_id != check.context_id
                or decision.principal_id != check.principal_id
                or decision.session_ref != check.session_ref
                or decision.permission != check.permission
                or decision.valid_through < request.requested_at
            ):
                raise OfflinePlanningPreviewError("preview authorization is invalid")
            record = self._reader.get(
                request.access.tenant_id,
                request.access.context_id,
                request.bundle_sha256,
            )
            if record is None:
                raise OfflinePlanningPreviewError("planning bundle was not found")
            if (
                not isinstance(record, PlanningBundleRecord)
                or record.tenant_id != request.access.tenant_id
                or record.context_id != request.access.context_id
                or record.bundle_sha256 != request.bundle_sha256
            ):
                raise OfflinePlanningPreviewError("stored planning tenant binding is invalid")
            bundle = record.bundle
            integrity = inspect_offline_api_planning_integrity(
                bundle=bundle, registry=self._registry
            )
            if (
                integrity["bundle_sha256"] != request.bundle_sha256
                or bundle["scope_sha256"] != request.expected_scope_sha256
            ):
                raise OfflinePlanningPreviewError("planning bundle binding is invalid")
            schedule = CoverageSchedule.from_dict(bundle["schedule"])
        except OfflinePlanningPreviewError:
            raise
        except (OfflineApiPlanningError, LocalApiServiceError, AttributeError, TypeError) as exc:
            raise OfflinePlanningPreviewError("planning preview sources are invalid") from exc
        body = {
            "schema_version": 1,
            "request_sha256": request.request_sha256,
            "tenant_id": request.access.tenant_id,
            "context_id": request.access.context_id,
            "bundle_sha256": integrity["bundle_sha256"],
            "scope_sha256": schedule.scope_sha256,
            "target_context_sha256": bundle["target_context_sha256"],
            "world_snapshot_sha256": schedule.world_snapshot_sha256,
            "schedule_sha256": schedule.schedule_sha256,
            "rehearsal_sha256": integrity["rehearsal_sha256"],
            "registry_binding_sha256": integrity["registry_binding_sha256"],
            "task_count": len(schedule.tasks),
            "task_types": dict(
                sorted(Counter(item.task_type.value for item in schedule.tasks).items())
            ),
            "blocked_reasons": [item.to_dict() for item in schedule.blocked_reasons],
            "effective_max_concurrency": schedule.effective_max_concurrency,
            "baseline_wave_count": bundle["capacity_rehearsal"]["baseline_wave_count"],
            "rehearsal_wave_count": bundle["capacity_rehearsal"]["rehearsal_wave_count"],
            "source_replay_performed": False,
            "positive_use_approved": False,
            "effects": dict(NO_EFFECTS),
        }
        return {
            **body,
            "preview_sha256": _digest({"domain": PREVIEW_DOMAIN, "preview": body}),
        }


__all__ = [
    "OfflinePlanningPreviewError",
    "OfflinePlanningPreviewService",
    "PlanningBundleRecord",
    "PlanningBundleReader",
    "PlanningPreviewRequest",
]
