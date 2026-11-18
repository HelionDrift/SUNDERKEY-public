"""Replay archived offline API planning from exact caller-supplied originals."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from .offline_api_planning_bundle import (
    OfflineApiPlanningError,
    build_offline_api_planning_bundle,
    verify_offline_api_planning_bundle,
)
from .offline_planning_preview import (
    OfflinePlanningPreviewError,
    PlanningBundleReader,
    PlanningBundleRecord,
)
from .offline_planning_preview_store import MAX_BUNDLE_BYTES

DOMAIN = "sunderkey.offline-verified-planning-preview.v1"
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_ARCHIVE_DEPTH = 64
MAX_ARCHIVE_NODES = 100_000
REPLAY_FIELDS = {
    "adapter",
    "sources",
    "batch",
    "scope",
    "observed_at",
    "expires_at",
    "capability_availability",
    "validator_availability",
    "limits",
    "specialist_capacity",
    "commander_capacity",
    "validator_capacity",
    "registry",
}
EFFECT_BOUNDARY = {
    "module_direct_authority": "none",
    "module_direct_execution": "none",
    "module_direct_finding_publication": "none",
    "module_direct_mutation": "none",
    "module_direct_network": "none",
    "injected_reader_and_analyzer_effects": "not_verified",
}


class OfflineVerifiedPlanningPreviewError(ValueError):
    """Raised when an archived plan cannot be replayed from pinned originals."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _bounded_archive_json(value: Any) -> str:
    """Bound a native JSON tree before whole-document serialization."""

    budget = MAX_BUNDLE_BYTES
    nodes = 0
    seen: set[int] = set()
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_ARCHIVE_NODES or depth > MAX_ARCHIVE_DEPTH:
            raise OfflineVerifiedPlanningPreviewError("planning archive exceeds structure limit")
        if type(item) is dict:
            if id(item) in seen or len(item) > MAX_ARCHIVE_NODES:
                raise OfflineVerifiedPlanningPreviewError("planning archive structure is invalid")
            seen.add(id(item))
            budget -= 2 + (2 * len(item) - 1 if item else 0)
            for key, child in item.items():
                if type(key) is not str:
                    raise OfflineVerifiedPlanningPreviewError(
                        "planning archive structure is invalid"
                    )
                stack.append((key, depth + 1))
                stack.append((child, depth + 1))
        elif type(item) is list:
            if id(item) in seen or len(item) > MAX_ARCHIVE_NODES:
                raise OfflineVerifiedPlanningPreviewError("planning archive structure is invalid")
            seen.add(id(item))
            budget -= 2 + (len(item) - 1 if item else 0)
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            if len(item) > budget:
                raise OfflineVerifiedPlanningPreviewError("planning archive exceeds size limit")
            budget -= len(json.encoder.encode_basestring_ascii(item))
        elif type(item) in (int, float, bool) or item is None:
            budget -= len(_canonical(item))
        else:
            raise OfflineVerifiedPlanningPreviewError("planning archive structure is invalid")
        if budget < 0:
            raise OfflineVerifiedPlanningPreviewError("planning archive exceeds size limit")
    document = _canonical(value)
    if len(document) > MAX_BUNDLE_BYTES:
        raise OfflineVerifiedPlanningPreviewError("planning archive exceeds size limit")
    return document


def build_offline_verified_planning_preview(
    *,
    reader: PlanningBundleReader,
    expected_tenant_id: str,
    expected_context_id: str,
    expected_bundle_sha256: str,
    expected_scope_sha256: str,
    planning_inputs: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay one archived plan without granting source custody or action authority.

    The caller must authorize the exact tenant and context before invoking this
    function. Neither the reader nor the supplied originals are trust roots.
    """

    if any(
        not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None
        for value in (expected_tenant_id, expected_context_id)
    ):
        raise OfflineVerifiedPlanningPreviewError("planning archive identity is invalid")
    if any(
        not isinstance(value, str) or SHA256_RE.fullmatch(value) is None
        for value in (expected_bundle_sha256, expected_scope_sha256)
    ):
        raise OfflineVerifiedPlanningPreviewError("planning archive digest is invalid")
    if (
        type(planning_inputs) is not dict
        or len(planning_inputs) not in (13, 14)
        or not (REPLAY_FIELDS <= set(planning_inputs) <= REPLAY_FIELDS | {"target_context"})
    ):
        raise OfflineVerifiedPlanningPreviewError("planning replay input fields are invalid")

    try:
        entry_bundle = build_offline_api_planning_bundle(**planning_inputs)
        entry_json = _bounded_archive_json(entry_bundle)
        if (
            entry_bundle["bundle_sha256"] != expected_bundle_sha256
            or entry_bundle["scope_sha256"] != expected_scope_sha256
        ):
            raise OfflineVerifiedPlanningPreviewError("planning source binding is invalid")
        record = reader.get(expected_tenant_id, expected_context_id, expected_bundle_sha256)
        if (
            not isinstance(record, PlanningBundleRecord)
            or record.tenant_id != expected_tenant_id
            or record.context_id != expected_context_id
            or record.bundle_sha256 != expected_bundle_sha256
        ):
            raise OfflineVerifiedPlanningPreviewError("planning archive binding is invalid")
        archive_json = _bounded_archive_json(record.bundle)
        if archive_json != entry_json:
            raise OfflineVerifiedPlanningPreviewError("planning archive differs from entry sources")
        archived_bundle = json.loads(archive_json)
        checked = verify_offline_api_planning_bundle(bundle=archived_bundle, **planning_inputs)
        if (
            checked["bundle_sha256"] != expected_bundle_sha256
            or checked["scope_sha256"] != expected_scope_sha256
            or planning_inputs["scope"].content_sha256 != expected_scope_sha256
        ):
            raise OfflineVerifiedPlanningPreviewError("planning archive binding is invalid")
    except OfflineVerifiedPlanningPreviewError:
        raise
    except (
        OfflineApiPlanningError,
        OfflinePlanningPreviewError,
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise OfflineVerifiedPlanningPreviewError(
            "planning archive or original sources are invalid"
        ) from exc

    body = {
        "schema_version": 1,
        "tenant_context_sha256": _digest(
            {"tenant_id": expected_tenant_id, "context_id": expected_context_id}
        ),
        "bundle_sha256": checked["bundle_sha256"],
        "batch_sha256": checked["batch_sha256"],
        "scope_sha256": checked["scope_sha256"],
        "target_context_sha256": checked["target_context_sha256"],
        "world_snapshot_sha256": checked["projection"]["snapshot"]["snapshot_sha256"],
        "schedule_sha256": checked["schedule"]["schedule_sha256"],
        "capacity_rehearsal_sha256": checked["capacity_rehearsal"]["rehearsal_sha256"],
        "registry_binding_sha256": checked["army_roster_binding"]["binding_sha256"],
        "source_replay_performed": True,
        "external_source_custody_verified": False,
        "live_currentness_verified": False,
        "caller_authorization_verified": False,
        "positive_use_approved": False,
        "effects": dict(EFFECT_BOUNDARY),
    }
    return {**body, "preview_sha256": _digest({"domain": DOMAIN, "body": body})}


__all__ = [
    "OfflineVerifiedPlanningPreviewError",
    "build_offline_verified_planning_preview",
]
