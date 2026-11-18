"""Negative-only review of one selected local API terminal assertion."""

from __future__ import annotations

import re
import sqlite3
import stat
from pathlib import Path
from typing import Any

from .local_api_runtime_adapter import SQLiteServiceRepository
from .local_api_service import ResourceKind, ResourceRecord, canonical_sha256

SCHEMA_VERSION = 1
MAX_DATABASE_BYTES = 32 * 1024 * 1024
MAX_WAL_BYTES = 16 * 1024 * 1024
MAX_SHM_BYTES = 4 * 1024 * 1024
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
FINDING_STATUSES = frozenset(
    {
        "discovered",
        "triaged",
        "validated",
        "accepted_risk",
        "false_positive",
        "remediated",
        "closed",
    }
)
FINDING_TERMINAL_ASSERTIONS = frozenset({"accepted_risk", "false_positive", "remediated", "closed"})
REMEDIATION_STATUSES = frozenset(
    {"guidance_ready", "resubmitted", "retest_pending", "closed", "reopened"}
)


class OfflineApiTerminalReviewError(ValueError):
    """Raised when a selected local record cannot be safely reviewed."""


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or IDENTIFIER_RE.fullmatch(value) is None:
        raise OfflineApiTerminalReviewError(f"{label} is invalid")
    return value


def _file_signature(path: Path, maximum: int, *, required: bool) -> tuple[int, ...] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if not required:
            return None
        raise OfflineApiTerminalReviewError("database file is absent") from None
    except OSError as exc:
        raise OfflineApiTerminalReviewError("database file cannot be inspected") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or getattr(metadata, "st_file_attributes", 0) & 0x400
    ):
        raise OfflineApiTerminalReviewError("database path is not a regular file")
    if metadata.st_size < 0 or metadata.st_size > maximum:
        raise OfflineApiTerminalReviewError("database file exceeds review byte limit")
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)


def _store_signature(repository: SQLiteServiceRepository) -> tuple[Any, ...]:
    path = repository.path
    if not isinstance(path, Path):
        raise OfflineApiTerminalReviewError("repository path is invalid")
    return (
        _file_signature(path, MAX_DATABASE_BYTES, required=True),
        _file_signature(Path(str(path) + "-wal"), MAX_WAL_BYTES, required=False),
        _file_signature(Path(str(path) + "-shm"), MAX_SHM_BYTES, required=False),
    )


def _review_status(record: ResourceRecord) -> tuple[str, str]:
    payload = record.payload
    if record.resource_kind is ResourceKind.FINDING:
        status = payload.get("status")
        if type(status) is not str or status not in FINDING_STATUSES:
            raise OfflineApiTerminalReviewError("finding status is unsupported")
        return status, (
            "terminal_assertion_unverified"
            if status in FINDING_TERMINAL_ASSERTIONS
            else "no_terminal_assertion_observed"
        )
    if record.resource_kind is ResourceKind.REMEDIATION:
        status = payload.get("closure_status")
        if type(status) is not str or status not in REMEDIATION_STATUSES:
            raise OfflineApiTerminalReviewError("remediation status is unsupported")
        return status, (
            "terminal_assertion_unverified"
            if status == "closed"
            else "no_terminal_assertion_observed"
        )
    raise OfflineApiTerminalReviewError("resource kind is unsupported")


def review_selected_api_terminal_assertion(
    *,
    repository: SQLiteServiceRepository,
    tenant_id: str,
    context_id: str,
    resource_kind: ResourceKind,
    resource_id: str,
) -> dict[str, Any]:
    """Flag one selected terminal assertion without approving any API state."""

    if type(repository) is not SQLiteServiceRepository:
        raise OfflineApiTerminalReviewError("repository must be SQLiteServiceRepository")
    tenant = _identifier(tenant_id, "tenant_id")
    context = _identifier(context_id, "context_id")
    resource = _identifier(resource_id, "resource_id")
    if type(resource_kind) is not ResourceKind or resource_kind not in {
        ResourceKind.FINDING,
        ResourceKind.REMEDIATION,
    }:
        raise OfflineApiTerminalReviewError("resource kind must be finding or remediation")

    before = _store_signature(repository)
    try:
        integrity_before = repository.verify_integrity()
        selected = repository.get(resource_kind, tenant, context, resource)
        integrity_after = repository.verify_integrity()
        repeated = repository.get(resource_kind, tenant, context, resource)
    except (sqlite3.Error, OSError, ValueError, KeyError, RuntimeError) as exc:
        raise OfflineApiTerminalReviewError("repository review failed") from exc
    after = _store_signature(repository)
    if (
        before != after
        or integrity_before != integrity_after
        or not isinstance(integrity_before, dict)
        or integrity_before.get("sqlite") != "ok"
        or type(selected) is not ResourceRecord
        or type(repeated) is not ResourceRecord
        or selected != repeated
    ):
        raise OfflineApiTerminalReviewError("selected repository observation changed")
    if (
        selected.resource_kind is not resource_kind
        or selected.tenant_id != tenant
        or selected.context_id != context
        or selected.resource_id != resource
    ):
        raise OfflineApiTerminalReviewError("selected record identity does not match")
    status, review_status = _review_status(selected)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": review_status,
        "tenant_id": tenant,
        "context_id": context,
        "resource_kind": resource_kind.value,
        "resource_id": resource,
        "resource_version": selected.version,
        "record_sha256": canonical_sha256(selected.to_dict()),
        "observed_api_status": status,
        "observation_scope": "one_selected_latest_local_record",
        "cross_read_atomicity": "not_proven",
        "live_source_currentness": "not_proven",
        "external_trust_root": "not_proven",
        "finding_snapshot_identity": "not_inferred",
        "closure_verified": False,
        "positive_use_approved": False,
        "authorization_effect": "none",
        "qualification_effect": "none",
        "target_effect": "none",
    }


__all__ = ["OfflineApiTerminalReviewError", "review_selected_api_terminal_assertion"]
