"""Concrete Phase194 authority bridge for Phase195 action resolution."""

from __future__ import annotations

import hashlib
import sqlite3
import unicodedata
from pathlib import Path
from typing import Any

from .action_resolution import (
    ActionResolutionError,
    CurrentExpertReviewClosure,
    _seal_current_expert_review_closure,
)
from .authenticated_expert_review import (
    SQLiteAuthenticatedExpertReviewCustody,
    VerifiedExpertReviewClosure,
)
from .errors import SunderkeyError
from .expert_review import ExpertReviewRecordSet
from .expert_runtime import RuntimePackCatalog
from .expert_workspace import (
    ExpertWorkspaceStoreAdapter,
    SQLiteExpertWorkspaceStore,
)
from .qualification import _canonical_json
from .registry import ExpertRegistry


class AuthenticatedExpertReviewClosureVerifierAdapter:
    """Verify a Phase195 review dependency through owned Phase194 custody."""

    def __init__(
        self,
        custody: SQLiteAuthenticatedExpertReviewCustody,
        registry: ExpertRegistry,
        *,
        workspace_store: ExpertWorkspaceStoreAdapter,
        runtime_catalog: RuntimePackCatalog,
    ) -> None:
        if type(custody) is not SQLiteAuthenticatedExpertReviewCustody:
            raise TypeError("custody must be authenticated Phase194 review custody")
        if type(registry) is not ExpertRegistry:
            raise TypeError("registry must be an ExpertRegistry")
        registry.validate()
        if not isinstance(workspace_store, ExpertWorkspaceStoreAdapter):
            raise TypeError(
                "workspace_store must implement ExpertWorkspaceStoreAdapter"
            )
        if type(runtime_catalog) is not RuntimePackCatalog:
            raise TypeError("runtime_catalog must be a RuntimePackCatalog")
        self._custody = custody
        self._registry = registry
        self._workspace_store = workspace_store
        self._runtime_catalog = runtime_catalog

    def verify_current(
        self,
        records: ExpertReviewRecordSet,
        registry: ExpertRegistry,
    ) -> CurrentExpertReviewClosure:
        if type(records) is not ExpertReviewRecordSet:
            raise ActionResolutionError("Expert review records are invalid")
        if registry is not self._registry:
            raise ActionResolutionError(
                "Expert review registry is not the adapter authority"
            )
        try:
            verified = self._custody.verify_closure(
                records.closure.closure_id,
                workspace_store=self._workspace_store,
                runtime_catalog=self._runtime_catalog,
            )
        except (KeyError, SunderkeyError, TypeError, ValueError) as exc:
            raise ActionResolutionError(
                "Phase194 expert review closure is not current"
            ) from exc
        return self._require_exact(verified, records)

    def verify_current_in_transaction(
        self,
        connection: sqlite3.Connection,
        records: ExpertReviewRecordSet,
        registry: ExpertRegistry,
    ) -> CurrentExpertReviewClosure:
        """Verify through Phase194 using the caller's locked transaction."""

        if type(records) is not ExpertReviewRecordSet:
            raise ActionResolutionError("Expert review records are invalid")
        if registry is not self._registry:
            raise ActionResolutionError(
                "Expert review registry is not the adapter authority"
            )
        try:
            verified = self._custody.verify_closure_in_transaction(
                connection,
                records.closure.closure_id,
                workspace_store=self._workspace_store,
                runtime_catalog=self._runtime_catalog,
            )
        except (KeyError, SunderkeyError, TypeError, ValueError) as exc:
            raise ActionResolutionError(
                "Phase194 expert review closure is not current"
            ) from exc
        return self._require_exact(verified, records)

    def _require_exact(
        self,
        verified: VerifiedExpertReviewClosure,
        records: ExpertReviewRecordSet,
    ) -> CurrentExpertReviewClosure:
        if (
            type(verified) is not VerifiedExpertReviewClosure
            or not self._custody.validates_closure_proof(verified)
            or verified.records != records
        ):
            raise ActionResolutionError(
                "Phase194 expert review closure is stale or substituted"
            )
        return _seal_current_expert_review_closure(verified.records)

    def open_local_workspace_guard(
        self,
        mission_connection: sqlite3.Connection,
        records: ExpertReviewRecordSet,
    ) -> tuple[sqlite3.Connection, dict[str, Any]]:
        """Hold an exact rollback-journal workspace snapshot through commit."""

        if type(self._workspace_store) is not SQLiteExpertWorkspaceStore:
            raise ActionResolutionError(
                "Local atomic action admission requires SQLite workspace custody"
            )
        if not mission_connection.in_transaction:
            raise ActionResolutionError(
                "MissionStore must be locked before the workspace guard"
            )
        workspace = self._workspace_store
        workspace_path = workspace.path.resolve()
        workspace_path_text = str(workspace_path)
        if (
            not workspace_path_text
            or len(workspace_path_text) > 32_767
            or any(
                unicodedata.category(character).startswith("C")
                for character in workspace_path_text
            )
        ):
            raise ActionResolutionError("Workspace path is not a safe exact path")
        if workspace_path == self._custody._store.path:
            raise ActionResolutionError(
                "Mission and workspace custody must use distinct databases"
            )
        connection = workspace._connect()
        try:
            journal_mode = str(
                connection.execute("PRAGMA journal_mode").fetchone()[0]
            ).lower()
            if journal_mode != "delete":
                raise ActionResolutionError(
                    "Workspace journal mode must be DELETE for atomic admission"
                )
            connection.execute("BEGIN")
            workspace._verify_identity(connection)
            high_water = self._workspace_high_water(
                mission_connection,
                connection,
                records,
                workspace_path,
            )
            return connection, high_water
        except Exception:
            connection.rollback()
            connection.close()
            raise

    def verify_local_workspace_guard(
        self,
        mission_connection: sqlite3.Connection,
        workspace_connection: sqlite3.Connection,
        records: ExpertReviewRecordSet,
        expected: dict[str, Any],
    ) -> None:
        if type(self._workspace_store) is not SQLiteExpertWorkspaceStore:
            raise ActionResolutionError("Workspace guard authority changed")
        actual = self._workspace_high_water(
            mission_connection,
            workspace_connection,
            records,
            self._workspace_store.path.resolve(),
        )
        if actual != expected:
            raise ActionResolutionError(
                "Workspace projection advanced during action admission"
            )

    @staticmethod
    def close_local_workspace_guard(connection: sqlite3.Connection) -> None:
        try:
            connection.rollback()
        finally:
            connection.close()

    def _workspace_high_water(
        self,
        mission_connection: sqlite3.Connection,
        connection: sqlite3.Connection,
        records: ExpertReviewRecordSet,
        workspace_path: Path,
    ) -> dict[str, Any]:
        document = records.snapshot.to_dict()
        workspace_id = document["workspace_id"]
        mission_identity = mission_connection.execute(
            "SELECT store_id FROM store_identity WHERE singleton_id = 1"
        ).fetchone()
        workspace_identity = connection.execute(
            "SELECT store_id FROM workspace_store_identity WHERE singleton = 1"
        ).fetchone()
        workspace_row = connection.execute(
            "SELECT * FROM expert_workspaces WHERE workspace_id = ?",
            (workspace_id,),
        ).fetchone()
        closure = connection.execute(
            "SELECT * FROM workspace_review_closure_imports WHERE workspace_id = ?",
            (workspace_id,),
        ).fetchone()
        revocation = connection.execute(
            "SELECT * FROM workspace_review_closure_revocations WHERE workspace_id = ?",
            (workspace_id,),
        ).fetchone()
        tail = connection.execute(
            """
            SELECT COUNT(*) AS event_count,
                   MAX(sequence_number) AS sequence_number
            FROM workspace_events WHERE workspace_id = ?
            """,
            (workspace_id,),
        ).fetchone()
        event = connection.execute(
            """
            SELECT event_sha256, occurred_at, workspace_revision, event_type
            FROM workspace_events WHERE workspace_id = ?
            ORDER BY sequence_number DESC LIMIT 1
            """,
            (workspace_id,),
        ).fetchone()
        if (
            mission_identity is None
            or workspace_identity is None
            or type(workspace_identity["store_id"]) is not str
            or workspace_row is None
            or closure is None
            or tail is None
            or event is None
            or revocation is not None
            or closure["closure_id"] != records.closure.closure_id
            or closure["closure_sha256"] != records.closure.closure_sha256
            or closure["snapshot_id"] != records.snapshot.snapshot_id
            or closure["snapshot_sha256"] != records.snapshot.snapshot_sha256
            or closure["mission_store_id"] != mission_identity["store_id"]
            or closure["disposition"] != "accepted"
            or workspace_row["mission_id"] != document["mission_id"]
            or workspace_row["plan_id"] != document["plan_id"]
            or workspace_row["revision"] != closure["workspace_revision"]
            or event["workspace_revision"] != workspace_row["revision"]
            or event["event_type"] != "review_closure_applied"
            or tail["event_count"] != tail["sequence_number"] + 1
        ):
            raise ActionResolutionError(
                "Workspace closure projection is absent, revoked, or inconsistent"
            )
        body = {
            "application_id": closure["application_id"],
            "application_sha256": closure["application_sha256"],
            "closure_id": closure["closure_id"],
            "closure_sha256": closure["closure_sha256"],
            "event_count": tail["event_count"],
            "event_head_occurred_at": event["occurred_at"],
            "event_head_sha256": event["event_sha256"],
            "mission_id": document["mission_id"],
            "mission_store_id": mission_identity["store_id"],
            "revocation_id": None,
            "revocation_sha256": None,
            "snapshot_id": closure["snapshot_id"],
            "snapshot_sha256": closure["snapshot_sha256"],
            "state": "closure_applied_unrevoked",
            "workspace_id": workspace_id,
            "workspace_revision": workspace_row["revision"],
            "workspace_store_id": workspace_identity["store_id"],
            "workspace_store_path": str(workspace_path),
        }
        digest = hashlib.sha256(
            _canonical_json(
                {
                    "domain": "sunderkey.action-workspace-high-water.v1",
                    "high_water": body,
                }
            ).encode("ascii")
        ).hexdigest()
        return {
            **body,
            "high_water_id": "AWH-" + digest[:32].upper(),
            "high_water_sha256": "sha256:" + digest,
        }


__all__ = ["AuthenticatedExpertReviewClosureVerifierAdapter"]
