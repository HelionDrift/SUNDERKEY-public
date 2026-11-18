"""Redacted historical action custody for one MissionStore mission.

This read-only projection does not grant current authority or invoke an adapter.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .action_authority_contracts import AuthenticatedProposalMaterialImport
from .action_resolution import (
    parse_action_proposal_resolution,
    parse_authenticated_action_admission_receipt,
)
from .authenticated_action_executor import parse_action_execution_terminal
from .expert_review import parse_expert_review_snapshot
from .mission import MISSION_ID_PATTERN
from .registry import ExpertRegistry
from .store import SCHEMA_VERSION, MissionStore, canonical_json

KIND = "sunderkey.offline-mission-action-custody.v3"
MAX_RECEIPTS = 100
MAX_SNAPSHOT_JSON_BYTES = 262_144
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TERMINAL_STATUSES = frozenset(
    {"completed", "failed_known", "predispatch_aborted", "indeterminate_quarantined"}
)
_AXIS_STATUSES = frozenset({"complete", "pending", "failed", "unknown"})
_OUTCOMES = frozenset({"succeeded", "failed", "indeterminate"})
_EFFECTS = {
    "action_authority": "none",
    "credential_access": "none",
    "network_call_performed": False,
    "qualification_effect": "none",
    "target_action_performed": False,
}
_MISSION_UNAVAILABLE = "mission action custody unavailable for expected tenant"


class OfflineMissionActionCustodyError(ValueError):
    """Raised when historical action custody cannot be safely projected."""


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise OfflineMissionActionCustodyError(f"{label} is invalid")
    return value


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value or len(value) > 256:
        raise OfflineMissionActionCustodyError(f"{label} is invalid")
    return value


def _optional(value: Any, label: str, validator: Any) -> Any:
    return None if value is None else validator(value, label)


def _identity(body: dict[str, Any]) -> tuple[str, str]:
    digest = "sha256:" + hashlib.sha256(
        (KIND + "\n" + canonical_json(body)).encode("ascii")
    ).hexdigest()
    return "MAC-" + digest[7:39].upper(), digest


def _check_receipt(raw: Any) -> None:
    fields = {
        "action_outcome", "evidence_status", "cleanup_status", "restoration_status",
        "execution_request_id", "execution_request_sha256", "execution_state",
        "proposal_import_id", "proposal_import_sha256", "proposal_product_id",
        "proposal_product_sha256", "admission_review_evidence_sha256",
        "origin_workspace_id", "origin_workspace_sha256", "origin_plan_id",
        "origin_work_id",
        "review_snapshot_id", "review_snapshot_sha256", "review_closure_id",
        "review_closure_sha256", "review_revocation_id", "review_revocation_sha256",
        "review_revocation_status",
        "receipt_id", "receipt_sha256", "revocation_id", "revocation_sha256",
        "tenant_id", "terminal_id", "terminal_sha256", "terminal_status",
    }
    if type(raw) is not dict or set(raw) != fields:
        raise OfflineMissionActionCustodyError("receipt summary fields are invalid")
    _text(raw["receipt_id"], "receipt_id")
    _digest(raw["receipt_sha256"], "receipt_sha256")
    _text(raw["tenant_id"], "tenant_id")
    for field in (
        "proposal_import_id", "proposal_product_id", "review_snapshot_id",
        "review_closure_id", "origin_workspace_id", "origin_plan_id",
        "origin_work_id",
    ):
        _text(raw[field], field)
    for field in (
        "proposal_import_sha256", "proposal_product_sha256",
        "admission_review_evidence_sha256", "review_snapshot_sha256",
        "review_closure_sha256", "origin_workspace_sha256",
    ):
        _digest(raw[field], field)
    for field in ("revocation_id", "execution_request_id", "terminal_id"):
        _optional(raw[field], field, _text)
    _optional(raw["review_revocation_id"], "review_revocation_id", _text)
    for field in ("revocation_sha256", "execution_request_sha256", "terminal_sha256"):
        _optional(raw[field], field, _digest)
    _optional(raw["review_revocation_sha256"], "review_revocation_sha256", _digest)
    if (raw["review_revocation_id"] is None) != (
        raw["review_revocation_sha256"] is None
    ):
        raise OfflineMissionActionCustodyError("review revocation binding is incomplete")
    expected_review_status = (
        "not_recorded" if raw["review_revocation_id"] is None else "recorded"
    )
    if raw["review_revocation_status"] != expected_review_status:
        raise OfflineMissionActionCustodyError("review revocation status is inconsistent")
    if (raw["revocation_id"] is None) != (raw["revocation_sha256"] is None):
        raise OfflineMissionActionCustodyError("revocation binding is incomplete")
    if (raw["execution_request_id"] is None) != (
        raw["execution_request_sha256"] is None
    ):
        raise OfflineMissionActionCustodyError("execution request binding is incomplete")
    if (raw["terminal_id"] is None) != (raw["terminal_sha256"] is None):
        raise OfflineMissionActionCustodyError("terminal binding is incomplete")
    if raw["execution_request_id"] is None:
        if raw["terminal_id"] is not None or any(
            raw[field] is not None
            for field in (
                "terminal_status", "action_outcome", "evidence_status",
                "cleanup_status", "restoration_status",
            )
        ):
            raise OfflineMissionActionCustodyError("unexecuted receipt has a terminal")
        expected_state = (
            "revoked_without_execution"
            if raw["revocation_id"] is not None
            else "admitted_without_execution"
        )
    elif raw["terminal_id"] is None:
        if any(
            raw[field] is not None
            for field in (
                "terminal_status", "action_outcome", "evidence_status",
                "cleanup_status", "restoration_status",
            )
        ):
            raise OfflineMissionActionCustodyError("missing terminal has outcome fields")
        expected_state = "terminal_missing_reconciliation_required"
    else:
        if raw["terminal_status"] not in _TERMINAL_STATUSES:
            raise OfflineMissionActionCustodyError("terminal status is invalid")
        if raw["action_outcome"] not in _OUTCOMES or any(
            raw[field] not in _AXIS_STATUSES
            for field in ("evidence_status", "cleanup_status", "restoration_status")
        ):
            raise OfflineMissionActionCustodyError("terminal outcome axes are invalid")
        expected_outcome = {
            "completed": "succeeded",
            "failed_known": "failed",
            "predispatch_aborted": "failed",
            "indeterminate_quarantined": "indeterminate",
        }[raw["terminal_status"]]
        if raw["action_outcome"] != expected_outcome:
            raise OfflineMissionActionCustodyError("terminal outcome is inconsistent")
        expected_state = raw["terminal_status"]
    if raw["execution_state"] != expected_state:
        raise OfflineMissionActionCustodyError("execution state is invalid")


@dataclass(frozen=True, slots=True)
class OfflineMissionActionCustodySnapshot:
    """Content-addressed, unsigned historical action status projection."""

    snapshot_id: str
    snapshot_sha256: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> OfflineMissionActionCustodySnapshot:
        """Check document shape and its public hash, not source authenticity."""

        fields = {
            "effects", "historical_integrity", "kind", "mission_head_sha256",
            "mission_id", "mission_revision", "receipt_count", "receipts",
            "schema_version", "snapshot_id", "snapshot_sha256", "tenant_id",
        }
        if type(raw) is not dict or set(raw) != fields:
            raise OfflineMissionActionCustodyError("snapshot fields are invalid")
        if (
            type(raw["schema_version"]) is not int
            or raw["schema_version"] != 3
            or raw["kind"] != KIND
            or type(raw["effects"]) is not dict
            or set(raw["effects"]) != set(_EFFECTS)
            or any(
                type(raw["effects"][key]) is not type(expected)
                or raw["effects"][key] != expected
                for key, expected in _EFFECTS.items()
            )
            or raw["historical_integrity"] != "verified_single_read_transaction"
        ):
            raise OfflineMissionActionCustodyError("snapshot boundary is invalid")
        if type(raw["mission_id"]) is not str or not MISSION_ID_PATTERN.fullmatch(
            raw["mission_id"]
        ):
            raise OfflineMissionActionCustodyError("mission_id is invalid")
        _text(raw["tenant_id"], "tenant_id")
        if type(raw["mission_revision"]) is not int or raw["mission_revision"] < 0:
            raise OfflineMissionActionCustodyError("mission revision is invalid")
        _digest(raw["mission_head_sha256"], "mission head digest")
        receipts = raw["receipts"]
        if type(receipts) is not list or not 1 <= len(receipts) <= MAX_RECEIPTS:
            raise OfflineMissionActionCustodyError("receipt list is invalid")
        if type(raw["receipt_count"]) is not int or raw["receipt_count"] != len(receipts):
            raise OfflineMissionActionCustodyError("receipt count is invalid")
        for receipt in receipts:
            _check_receipt(receipt)
            if receipt["tenant_id"] != raw["tenant_id"]:
                raise OfflineMissionActionCustodyError("receipt crosses the tenant boundary")
        ids = [receipt["receipt_id"] for receipt in receipts]
        if ids != sorted(set(ids)):
            raise OfflineMissionActionCustodyError("receipt order is invalid")
        body = {
            key: value for key, value in raw.items()
            if key not in {"snapshot_id", "snapshot_sha256"}
        }
        snapshot_id, snapshot_sha256 = _identity(body)
        if raw["snapshot_id"] != snapshot_id or raw["snapshot_sha256"] != snapshot_sha256:
            raise OfflineMissionActionCustodyError("snapshot content address is invalid")
        document = canonical_json(raw)
        if len(document) > MAX_SNAPSHOT_JSON_BYTES:
            raise OfflineMissionActionCustodyError("snapshot document exceeds the byte bound")
        return cls(snapshot_id, snapshot_sha256, document)

    @classmethod
    def from_json(cls, document: str) -> OfflineMissionActionCustodySnapshot:
        if type(document) is not str:
            raise OfflineMissionActionCustodyError("snapshot document must be text")
        if len(document) > MAX_SNAPSHOT_JSON_BYTES:
            raise OfflineMissionActionCustodyError("snapshot document exceeds the byte bound")
        try:
            encoded_size = len(document.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise OfflineMissionActionCustodyError("snapshot document is invalid") from exc
        if encoded_size > MAX_SNAPSHOT_JSON_BYTES:
            raise OfflineMissionActionCustodyError("snapshot document exceeds the byte bound")
        try:
            raw = json.loads(document)
        except (ValueError, RecursionError) as exc:
            raise OfflineMissionActionCustodyError("snapshot document is invalid") from exc
        snapshot = cls.from_dict(raw)
        if snapshot.document_json != document:
            raise OfflineMissionActionCustodyError("snapshot document is not canonical")
        return snapshot


def capture_offline_mission_action_custody(
    store: MissionStore,
    registry: ExpertRegistry,
    mission_id: str,
    *,
    expected_tenant_id: str,
) -> OfflineMissionActionCustodySnapshot:
    """Verify historical custody and summarize one mission without target effects."""

    if type(store) is not MissionStore or not isinstance(registry, ExpertRegistry):
        raise OfflineMissionActionCustodyError("MissionStore and registry are required")
    if type(mission_id) is not str or MISSION_ID_PATTERN.fullmatch(mission_id) is None:
        raise OfflineMissionActionCustodyError("mission_id is invalid")
    tenant_id = _text(expected_tenant_id, "expected_tenant_id")
    with store._read_connection() as connection:
        connection.execute("PRAGMA query_only = ON")
        store._quick_check(connection)
        store._foreign_key_check(connection)
        store._require_schema(connection)
        store._verify_connection(
            connection,
            registry,
            schema_version=SCHEMA_VERSION,
            require_current_action_sources=False,
        )
        mission_row = connection.execute(
            "SELECT * FROM missions WHERE mission_id = ?", (mission_id,)
        ).fetchone()
        if mission_row is None:
            raise OfflineMissionActionCustodyError(_MISSION_UNAVAILABLE)
        mission = store._stored_mission_from_row(connection, registry, mission_row)
        foreign_tenant_count = connection.execute(
            "SELECT COUNT(*) FROM action_admission_receipts "
            "WHERE mission_id = ? AND tenant_id <> ?",
            (mission_id, tenant_id),
        ).fetchone()[0]
        if foreign_tenant_count:
            raise OfflineMissionActionCustodyError(_MISSION_UNAVAILABLE)
        rows = connection.execute(
            "SELECT r.receipt_id, r.receipt_sha256, r.tenant_id, r.receipt_json, "
            "r.resolution_json, r.review_evidence_json, r.review_evidence_sha256, "
            "v.revocation_id, v.revocation_sha256, "
            "c.consumption_id, x.request_id, x.request_sha256, "
            "t.terminal_id, t.terminal_sha256, t.terminal_status, t.terminal_json "
            "FROM action_admission_receipts AS r "
            "LEFT JOIN action_admission_revocations AS v ON v.receipt_id = r.receipt_id "
            "LEFT JOIN action_admission_execution_consumptions AS c "
            "ON c.receipt_id = r.receipt_id "
            "LEFT JOIN action_execution_requests AS x ON x.receipt_id = r.receipt_id "
            "LEFT JOIN action_execution_terminals AS t ON t.request_id = x.request_id "
            "WHERE r.mission_id = ? AND r.tenant_id = ? "
            "ORDER BY r.receipt_id LIMIT ?",
            (mission_id, tenant_id, MAX_RECEIPTS + 1),
        ).fetchall()
        if len(rows) > MAX_RECEIPTS:
            raise OfflineMissionActionCustodyError("mission receipt count exceeds the bound")
        if not rows:
            raise OfflineMissionActionCustodyError(_MISSION_UNAVAILABLE)
        receipts: list[dict[str, Any]] = []
        for row in rows:
            receipt = parse_authenticated_action_admission_receipt(
                json.loads(row["receipt_json"])
            )
            resolution = parse_action_proposal_resolution(
                json.loads(row["resolution_json"])
            ).to_dict()
            if (
                receipt.receipt_id != row["receipt_id"]
                or receipt.receipt_sha256 != row["receipt_sha256"]
                or receipt.to_dict()["mission_id"] != mission_id
                or receipt.to_dict()["tenant_id"] != row["tenant_id"]
                or resolution["mission_id"] != mission_id
                or resolution["tenant_id"] != tenant_id
            ):
                raise OfflineMissionActionCustodyError("receipt binding is invalid")
            proposal = connection.execute(
                "SELECT proposal_import_id, proposal_import_sha256, proposal_json, "
                "tenant_id, mission_id, plan_id, "
                "product_id, product_sha256, review_snapshot_id, "
                "review_snapshot_sha256, review_closure_id, review_closure_sha256 "
                "FROM action_authority_proposal_imports WHERE product_id = ?",
                (resolution["proposal_product_id"],),
            ).fetchone()
            if proposal is None or any(
                proposal[field] != expected
                for field, expected in {
                    "tenant_id": tenant_id,
                    "mission_id": mission_id,
                    "plan_id": resolution["plan_id"],
                    "product_id": resolution["proposal_product_id"],
                    "product_sha256": resolution["proposal_product_sha256"],
                    "review_snapshot_id": resolution["review_snapshot_id"],
                    "review_snapshot_sha256": resolution["review_snapshot_sha256"],
                    "review_closure_id": resolution["review_closure_id"],
                    "review_closure_sha256": resolution["review_closure_sha256"],
                }.items()
            ):
                raise OfflineMissionActionCustodyError("review proposal binding is invalid")
            proposal_document = AuthenticatedProposalMaterialImport.from_dict(
                json.loads(proposal["proposal_json"])
            ).to_dict()
            review_evidence = json.loads(row["review_evidence_json"])
            historical_snapshot = parse_expert_review_snapshot(
                review_evidence["snapshot"], registry
            ).to_dict()
            reviewed_product = proposal_document["reviewed_product"]
            matching_products = [
                product for product in historical_snapshot["products"]
                if product["work_id"] == resolution["proposal_work_id"]
            ]
            if (
                proposal_document["proposal_import_id"] != proposal["proposal_import_id"]
                or proposal_document["proposal_import_sha256"]
                != proposal["proposal_import_sha256"]
                or any(
                    proposal_document[field] != expected
                    for field, expected in {
                        "tenant_id": tenant_id,
                        "mission_id": mission_id,
                        "plan_id": resolution["plan_id"],
                        "review_snapshot_id": proposal["review_snapshot_id"],
                        "review_snapshot_sha256": proposal["review_snapshot_sha256"],
                        "review_closure_id": proposal["review_closure_id"],
                        "review_closure_sha256": proposal["review_closure_sha256"],
                    }.items()
                )
                or any(
                    historical_snapshot[field] != expected
                    for field, expected in {
                        "tenant_id": tenant_id,
                        "mission_id": mission_id,
                        "plan_id": resolution["plan_id"],
                        "workspace_id": proposal_document["workspace_id"],
                        "snapshot_id": proposal["review_snapshot_id"],
                        "snapshot_sha256": proposal["review_snapshot_sha256"],
                    }.items()
                )
                or len(matching_products) != 1
                or any(
                    product[field] != expected
                    for product in (reviewed_product, matching_products[0])
                    for field, expected in {
                        "work_id": resolution["proposal_work_id"],
                        "product_id": proposal["product_id"],
                        "product_sha256": proposal["product_sha256"],
                    }.items()
                )
            ):
                raise OfflineMissionActionCustodyError("action origin binding is invalid")
            review_revocation = connection.execute(
                "SELECT mission_id, closure_sha256, revocation_id, revocation_sha256 "
                "FROM authenticated_expert_review_revocations WHERE closure_id = ?",
                (proposal["review_closure_id"],),
            ).fetchone()
            if review_revocation is not None and (
                review_revocation["mission_id"] != mission_id
                or review_revocation["closure_sha256"] != proposal["review_closure_sha256"]
            ):
                raise OfflineMissionActionCustodyError("review revocation binding is invalid")
            if (row["consumption_id"] is None) != (row["request_id"] is None):
                raise OfflineMissionActionCustodyError("execution consumption is incomplete")
            terminal = (
                None
                if row["terminal_json"] is None
                else parse_action_execution_terminal(json.loads(row["terminal_json"])).to_dict()
            )
            if terminal is not None and (
                terminal["request_id"] != row["request_id"]
                or terminal["action_execution_terminal_id"] != row["terminal_id"]
                or terminal["action_execution_terminal_sha256"] != row["terminal_sha256"]
                or terminal["terminal_status"] != row["terminal_status"]
            ):
                raise OfflineMissionActionCustodyError("terminal binding is invalid")
            if row["request_id"] is None:
                state = (
                    "revoked_without_execution"
                    if row["revocation_id"] is not None
                    else "admitted_without_execution"
                )
            elif terminal is None:
                state = "terminal_missing_reconciliation_required"
            else:
                state = terminal["terminal_status"]
            receipts.append(
                {
                    "receipt_id": row["receipt_id"],
                    "receipt_sha256": row["receipt_sha256"],
                    "tenant_id": row["tenant_id"],
                    "proposal_import_id": proposal["proposal_import_id"],
                    "proposal_import_sha256": proposal["proposal_import_sha256"],
                    "proposal_product_id": proposal["product_id"],
                    "proposal_product_sha256": proposal["product_sha256"],
                    "origin_workspace_id": proposal_document["workspace_id"],
                    "origin_workspace_sha256": historical_snapshot["workspace_sha256"],
                    "origin_plan_id": resolution["plan_id"],
                    "origin_work_id": resolution["proposal_work_id"],
                    "admission_review_evidence_sha256": row["review_evidence_sha256"],
                    "review_snapshot_id": proposal["review_snapshot_id"],
                    "review_snapshot_sha256": proposal["review_snapshot_sha256"],
                    "review_closure_id": proposal["review_closure_id"],
                    "review_closure_sha256": proposal["review_closure_sha256"],
                    "review_revocation_id": (
                        None if review_revocation is None
                        else review_revocation["revocation_id"]
                    ),
                    "review_revocation_sha256": (
                        None if review_revocation is None
                        else review_revocation["revocation_sha256"]
                    ),
                    "review_revocation_status": (
                        "not_recorded" if review_revocation is None else "recorded"
                    ),
                    "revocation_id": row["revocation_id"],
                    "revocation_sha256": row["revocation_sha256"],
                    "execution_request_id": row["request_id"],
                    "execution_request_sha256": row["request_sha256"],
                    "terminal_id": row["terminal_id"],
                    "terminal_sha256": row["terminal_sha256"],
                    "terminal_status": None if terminal is None else terminal["terminal_status"],
                    "action_outcome": None if terminal is None else terminal["action_outcome"],
                    "evidence_status": None if terminal is None else terminal["evidence_status"],
                    "cleanup_status": None if terminal is None else terminal["cleanup_status"],
                    "restoration_status": (
                        None if terminal is None else terminal["restoration_status"]
                    ),
                    "execution_state": state,
                }
            )
    body = {
        "effects": dict(_EFFECTS),
        "historical_integrity": "verified_single_read_transaction",
        "kind": KIND,
        "mission_head_sha256": mission.head_hash,
        "mission_id": mission_id,
        "mission_revision": mission.revision,
        "receipt_count": len(receipts),
        "receipts": receipts,
        "schema_version": 3,
        "tenant_id": tenant_id,
    }
    snapshot_id, snapshot_sha256 = _identity(body)
    return OfflineMissionActionCustodySnapshot.from_dict(
        {**body, "snapshot_id": snapshot_id, "snapshot_sha256": snapshot_sha256}
    )


def verify_offline_mission_action_custody_snapshot(
    snapshot: OfflineMissionActionCustodySnapshot,
    store: MissionStore,
    registry: ExpertRegistry,
    *,
    expected_tenant_id: str,
) -> None:
    """Reobserve one mission and require exact current store content equality.

    A successful check establishes agreement during a fresh historical store
    read only. It does not authenticate the store or grant live use.
    """

    if type(snapshot) is not OfflineMissionActionCustodySnapshot:
        raise OfflineMissionActionCustodyError("typed snapshot is required")
    parsed = OfflineMissionActionCustodySnapshot.from_json(snapshot.document_json)
    if parsed != snapshot:
        raise OfflineMissionActionCustodyError("snapshot object binding is invalid")
    if parsed.to_dict()["tenant_id"] != _text(expected_tenant_id, "expected_tenant_id"):
        raise OfflineMissionActionCustodyError("snapshot tenant boundary is invalid")
    current = capture_offline_mission_action_custody(
        store,
        registry,
        parsed.to_dict()["mission_id"],
        expected_tenant_id=expected_tenant_id,
    )
    if current.document_json != parsed.document_json:
        raise OfflineMissionActionCustodyError(
            "snapshot does not match the current historical store custody"
        )
