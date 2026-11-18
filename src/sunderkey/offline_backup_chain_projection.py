"""Project supplied backup chains and restore-point lag without storage access."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_backup_chain_projection"
PROFILE_ID = "AOE-GB-D07-S13"
CAPABILITY_ID = "army.gb.d07.s13"
VECTOR_ID = "AV-GB-D07-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D07-S13"
WAVE_ID = "IW2-013"
COMMANDER_ID = "AOE-GB-D07-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:0324bcde42564c06ef99c0e204e7f60f2e0504486c14408c777efbaef5d26c39"
SEMANTICS_PROFILE = "supplied-backup-chain-v1"
DOMAIN = "sunderkey.offline-backup-chain-projection.v1"
MAX_SNAPSHOTS = 256
MAX_OBJECTIVES = 16
MAX_TICK = 1_000_000_000_000
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DATASET = re.compile(r"dataset:sha256:[0-9a-f]{64}\Z")
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "filesystem",
        "network",
        "provider",
        "publication",
        "qualification",
        "restore",
        "storage",
        "target",
    ),
    "none",
)


class BackupChainProjectionError(ValueError):
    """The supplied backup model or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise BackupChainProjectionError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise BackupChainProjectionError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise BackupChainProjectionError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise BackupChainProjectionError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise BackupChainProjectionError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise BackupChainProjectionError("Native JSON text keys are required")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        finally:
            active.remove(id(item))

    visit(value, 1)
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise BackupChainProjectionError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise BackupChainProjectionError(f"{label} fields are invalid")


def _tick(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_TICK:
        raise BackupChainProjectionError(f"{label} tick is invalid")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "dataset_ref",
            "as_of_tick",
            "history_complete",
            "snapshots",
            "objectives",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise BackupChainProjectionError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise BackupChainProjectionError("Semantics profile is invalid")
    if type(model["dataset_ref"]) is not str or _DATASET.fullmatch(model["dataset_ref"]) is None:
        raise BackupChainProjectionError("Dataset must be an opaque digest reference")
    as_of = _tick(model["as_of_tick"], "Assessment")
    if type(model["history_complete"]) is not bool:
        raise BackupChainProjectionError("History completeness must be an exact boolean")
    snapshots = model["snapshots"]
    if type(snapshots) is not list or len(snapshots) > MAX_SNAPSHOTS:
        raise BackupChainProjectionError("Snapshot count is invalid")
    by_id: dict[str, dict] = {}
    for row in snapshots:
        _fields(
            row,
            {
                "snapshot_id",
                "recorded_tick",
                "expires_tick",
                "parent_snapshot_id",
                "declared_restorable",
            },
            "snapshot",
        )
        snapshot_id = row["snapshot_id"]
        if type(snapshot_id) is not str or _ID.fullmatch(snapshot_id) is None:
            raise BackupChainProjectionError("Snapshot identifier is invalid")
        if snapshot_id in by_id:
            raise BackupChainProjectionError("Duplicate snapshot identifier")
        recorded = _tick(row["recorded_tick"], "Recorded")
        expires = _tick(row["expires_tick"], "Expiry")
        if not recorded <= as_of or expires < recorded:
            raise BackupChainProjectionError("Snapshot temporal order is invalid")
        parent = row["parent_snapshot_id"]
        if parent is not None and (type(parent) is not str or _ID.fullmatch(parent) is None):
            raise BackupChainProjectionError("Parent identifier is invalid")
        if type(row["declared_restorable"]) is not bool:
            raise BackupChainProjectionError("Restorable assertion must be an exact boolean")
        by_id[snapshot_id] = row
    for row in snapshots:
        parent_id = row["parent_snapshot_id"]
        if parent_id is not None and (
            parent_id not in by_id or by_id[parent_id]["recorded_tick"] >= row["recorded_tick"]
        ):
            raise BackupChainProjectionError("Parent must be a supplied older snapshot")
    objectives = model["objectives"]
    if type(objectives) is not list or not 1 <= len(objectives) <= MAX_OBJECTIVES:
        raise BackupChainProjectionError("Objective count is invalid")
    seen: set[int] = set()
    for objective in objectives:
        _fields(objective, {"target_tick", "maximum_lag_ticks"}, "objective")
        target = _tick(objective["target_tick"], "Target")
        _tick(objective["maximum_lag_ticks"], "Maximum lag")
        if target > as_of or target in seen:
            raise BackupChainProjectionError("Objective target is invalid or duplicate")
        seen.add(target)
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    by_id = {row["snapshot_id"]: row for row in plan["snapshots"]}
    chain_cache: dict[str, tuple[str, ...] | None] = {}
    as_of = plan["as_of_tick"]

    def chain(snapshot_id: str) -> tuple[str, ...] | None:
        if snapshot_id in chain_cache:
            return chain_cache[snapshot_id]
        row = by_id[snapshot_id]
        if not row["declared_restorable"] or row["expires_tick"] < as_of:
            result = None
        elif row["parent_snapshot_id"] is None:
            result = (snapshot_id,)
        else:
            prior = chain(row["parent_snapshot_id"])
            result = (*prior, snapshot_id) if prior is not None else None
        chain_cache[snapshot_id] = result
        return result

    rows = []
    for objective in plan["objectives"]:
        target = objective["target_tick"]
        candidates = [
            row
            for row in plan["snapshots"]
            if row["recorded_tick"] <= target and chain(row["snapshot_id"]) is not None
        ]
        if candidates:
            selected = max(candidates, key=lambda row: (row["recorded_tick"], row["snapshot_id"]))
            snapshot_id = selected["snapshot_id"]
            lag = target - selected["recorded_tick"]
            disposition = (
                "within_supplied_lag"
                if lag <= objective["maximum_lag_ticks"]
                else "exceeds_supplied_lag"
            )
            chain_ids = list(chain(snapshot_id) or ())
        else:
            snapshot_id = None
            lag = None
            chain_ids = []
            disposition = (
                "no_supplied_chain" if plan["history_complete"] else "unknown_incomplete_history"
            )
        rows.append(
            {
                "target_tick": target,
                "maximum_lag_ticks": objective["maximum_lag_ticks"],
                "disposition": disposition,
                "selected_snapshot_id": snapshot_id,
                "declared_chain_ids": chain_ids,
                "lag_ticks": lag,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "objectives": rows,
        "flags": {
            "snapshot_bytes_verified": False,
            "storage_retention_verified": False,
            "restore_executed": False,
            "recoverability_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Snapshot times, parent links, expiry, restorability, and "
            "completeness are caller-supplied.",
            "A declared chain or lag result does not prove backup integrity "
            "or a successful restore.",
            "Only abstract integer ticks are compared; no real time or "
            "retention policy is inferred.",
            "No storage, provider, backup service, credential, network, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "BCP-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class BackupChainProjection:
    """Immutable report replayed from its exact supplied model."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise BackupChainProjectionError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise BackupChainProjectionError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_backup_chain(model: Any) -> BackupChainProjection:
    """Project only the supplied parent chain and declared restore-point lag."""
    return BackupChainProjection(_derive(model))


def verify_supplied_backup_chain(report: Any, *, model: Any) -> BackupChainProjection:
    if type(report) is not BackupChainProjection:
        raise BackupChainProjectionError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise BackupChainProjectionError("Report differs from supplied model replay")
    return BackupChainProjection(expected)
