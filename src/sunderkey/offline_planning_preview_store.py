"""Local-only SQLite custody for synthetic planning preview archives."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from .offline_api_planning_bundle import (
    OfflineApiPlanningError,
    inspect_offline_api_planning_integrity,
)
from .offline_planning_preview import OfflinePlanningPreviewError, PlanningBundleRecord
from .registry import ExpertRegistry

SCHEMA_VERSION = 1
MAX_BUNDLE_BYTES = 2_000_000
CREATE_SQL = (
    "CREATE TABLE planning_bundles ("
    "tenant_id TEXT NOT NULL, "
    "context_id TEXT NOT NULL, "
    "bundle_sha256 TEXT NOT NULL PRIMARY KEY, "
    "bundle_json TEXT NOT NULL, "
    "CHECK (length(bundle_json) > 0)"
    ")"
)


class OfflinePlanningPreviewStoreError(OfflinePlanningPreviewError):
    """Raised when local archive schema, custody, or content is invalid."""


class SQLitePlanningBundleStore:
    """Explicit local store, never exposed as an API write operation."""

    def __init__(self, path: Path, registry: ExpertRegistry) -> None:
        if not isinstance(path, Path) or not path.parent.is_dir():
            raise OfflinePlanningPreviewStoreError("local store parent must exist")
        if not isinstance(registry, ExpertRegistry):
            raise OfflinePlanningPreviewStoreError("typed Army registry is required")
        self.path = path.resolve()
        self.registry = registry
        try:
            with closing(self._open()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                tables = {
                    item[0]: item[1]
                    for item in connection.execute(
                        "SELECT name, sql FROM sqlite_master "
                        "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    ).fetchall()
                }
                if version == 0 and not tables:
                    connection.execute(CREATE_SQL)
                    connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                elif version != SCHEMA_VERSION or tables != {"planning_bundles": CREATE_SQL}:
                    raise OfflinePlanningPreviewStoreError("local store schema is invalid")
                connection.commit()
        except sqlite3.Error as exc:
            raise OfflinePlanningPreviewStoreError("local store cannot initialize") from exc

    def _open(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _document(self, record: PlanningBundleRecord) -> str:
        if not isinstance(record, PlanningBundleRecord):
            raise OfflinePlanningPreviewStoreError("typed planning record is required")
        try:
            integrity = inspect_offline_api_planning_integrity(
                bundle=record.bundle, registry=self.registry
            )
            if integrity["bundle_sha256"] != record.bundle_sha256:
                raise OfflinePlanningPreviewStoreError("stored bundle digest differs")
            document = json.dumps(
                record.bundle,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        except (OfflineApiPlanningError, TypeError, ValueError) as exc:
            if isinstance(exc, OfflinePlanningPreviewStoreError):
                raise
            raise OfflinePlanningPreviewStoreError("planning archive is invalid") from exc
        if len(document.encode("ascii")) > MAX_BUNDLE_BYTES:
            raise OfflinePlanningPreviewStoreError("planning archive is too large")
        return document

    def put(self, record: PlanningBundleRecord) -> None:
        """Import one already-built synthetic archive through an explicit local call."""

        document = self._document(record)
        try:
            with closing(self._open()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT tenant_id, context_id, bundle_json FROM planning_bundles "
                    "WHERE bundle_sha256=?",
                    (record.bundle_sha256,),
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO planning_bundles "
                        "(tenant_id, context_id, bundle_sha256, bundle_json) "
                        "VALUES (?, ?, ?, ?)",
                        (
                            record.tenant_id,
                            record.context_id,
                            record.bundle_sha256,
                            document,
                        ),
                    )
                elif row != (record.tenant_id, record.context_id, document):
                    raise OfflinePlanningPreviewStoreError("planning archive identity conflicts")
                connection.commit()
        except sqlite3.Error as exc:
            raise OfflinePlanningPreviewStoreError("planning archive import failed") from exc

    def get(
        self, tenant_id: str, context_id: str, bundle_sha256: str
    ) -> PlanningBundleRecord | None:
        """Read one exact tenant/context key and recheck content integrity."""

        try:
            with closing(self._open()) as connection:
                row = connection.execute(
                    "SELECT tenant_id, context_id, bundle_sha256, bundle_json "
                    "FROM planning_bundles "
                    "WHERE tenant_id=? AND context_id=? AND bundle_sha256=?",
                    (tenant_id, context_id, bundle_sha256),
                ).fetchone()
            if row is None:
                return None
            document: Any = json.loads(row[3])
            record = PlanningBundleRecord(row[0], row[1], row[2], document)
            self._document(record)
            return record
        except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError) as exc:
            if isinstance(exc, OfflinePlanningPreviewStoreError):
                raise
            raise OfflinePlanningPreviewStoreError("stored planning archive is invalid") from exc


__all__ = ["OfflinePlanningPreviewStoreError", "SQLitePlanningBundleStore"]
