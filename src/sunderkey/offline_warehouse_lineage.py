"""Project supplied warehouse and lake lineage without data-system access."""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_warehouse_lineage"
PROFILE_ID = "AOE-GB-D07-S09"
CAPABILITY_ID = "army.gb.d07.s09"
VECTOR_ID = "AV-GB-D07-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D07-S09"
WAVE_ID = "IW2-009"
COMMANDER_ID = "AOE-GB-D07-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:b3b75963f5f4fa8faf107ed52504a49811d6d96d2d675842eed2e5a0c5c2f590"
SEMANTICS_PROFILE = "supplied-warehouse-lineage-v1"
DOMAIN = "sunderkey.offline-warehouse-lineage.v1"
MAX_DATASETS = 128
MAX_TRANSFERS = 512
MAX_OBJECTIVES = 16
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DATASET = re.compile(r"dataset:sha256:[0-9a-f]{64}\Z")
_TENANT = re.compile(r"tenant:sha256:[0-9a-f]{64}\Z")
_REGION = re.compile(r"region:sha256:[0-9a-f]{64}\Z")
_STATES = frozenset(("declared_included", "declared_excluded", "unknown"))
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "data_movement",
        "execution",
        "filesystem",
        "network",
        "provider",
        "publication",
        "qualification",
        "query",
        "target",
    ),
    "none",
)


class WarehouseLineageError(ValueError):
    """A supplied lineage model or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise WarehouseLineageError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise WarehouseLineageError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise WarehouseLineageError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise WarehouseLineageError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise WarehouseLineageError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise WarehouseLineageError("Native JSON text keys are required")
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
        raise WarehouseLineageError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise WarehouseLineageError(f"{label} fields are invalid")


def _ref(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise WarehouseLineageError(f"{label} must be an opaque digest reference")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "lineage_complete",
            "datasets",
            "transfers",
            "objectives",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WarehouseLineageError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise WarehouseLineageError("Semantics profile is invalid")
    if type(model["lineage_complete"]) is not bool:
        raise WarehouseLineageError("Lineage completeness must be an exact boolean")
    datasets = model["datasets"]
    transfers = model["transfers"]
    objectives = model["objectives"]
    if type(datasets) is not list or not 1 <= len(datasets) <= MAX_DATASETS:
        raise WarehouseLineageError("Dataset count is invalid")
    if type(transfers) is not list or len(transfers) > MAX_TRANSFERS:
        raise WarehouseLineageError("Transfer count is invalid")
    if type(objectives) is not list or not 1 <= len(objectives) <= MAX_OBJECTIVES:
        raise WarehouseLineageError("Objective count is invalid")
    known: set[str] = set()
    for row in datasets:
        _fields(row, {"dataset_ref", "tenant_ref", "region_ref"}, "dataset")
        dataset = _ref(row["dataset_ref"], _DATASET, "Dataset")
        if dataset in known:
            raise WarehouseLineageError("Duplicate dataset reference")
        known.add(dataset)
        _ref(row["tenant_ref"], _TENANT, "Dataset tenant")
        _ref(row["region_ref"], _REGION, "Dataset region")
    transfer_ids: set[str] = set()
    transfer_pairs: set[tuple[str, str]] = set()
    for row in transfers:
        _fields(
            row,
            {"transfer_id", "source_dataset_ref", "output_dataset_ref", "state"},
            "transfer",
        )
        transfer_id = row["transfer_id"]
        if type(transfer_id) is not str or _ID.fullmatch(transfer_id) is None:
            raise WarehouseLineageError("Transfer identifier is invalid")
        pair = (
            _ref(row["source_dataset_ref"], _DATASET, "Source dataset"),
            _ref(row["output_dataset_ref"], _DATASET, "Output dataset"),
        )
        if pair[0] not in known or pair[1] not in known:
            raise WarehouseLineageError("Transfer dataset is undeclared")
        if transfer_id in transfer_ids or pair in transfer_pairs:
            raise WarehouseLineageError("Duplicate or contradictory transfer")
        transfer_ids.add(transfer_id)
        transfer_pairs.add(pair)
        if type(row["state"]) is not str or row["state"] not in _STATES:
            raise WarehouseLineageError("Transfer state is invalid")
    seen: set[tuple[str, str, str]] = set()
    for row in objectives:
        _fields(
            row,
            {"output_dataset_ref", "expected_tenant_ref", "expected_region_ref"},
            "objective",
        )
        key = (
            _ref(row["output_dataset_ref"], _DATASET, "Objective output"),
            _ref(row["expected_tenant_ref"], _TENANT, "Expected tenant"),
            _ref(row["expected_region_ref"], _REGION, "Expected region"),
        )
        if key[0] not in known or key in seen:
            raise WarehouseLineageError("Objective is undeclared or duplicated")
        seen.add(key)
    return model


def _paths(plan: dict, output: str, *, include_unknown: bool) -> dict[str, tuple[str, ...]]:
    reverse_edges: dict[str, list[tuple[str, str]]] = {}
    for row in plan["transfers"]:
        if row["state"] == "declared_included" or (
            include_unknown and row["state"] == "unknown"
        ):
            reverse_edges.setdefault(row["output_dataset_ref"], []).append(
                (row["transfer_id"], row["source_dataset_ref"])
            )
    paths = {output: ()}
    queue = deque([output])
    while queue:
        dataset = queue.popleft()
        for transfer_id, source in sorted(reverse_edges.get(dataset, [])):
            if source not in paths:
                paths[source] = (*paths[dataset], transfer_id)
                queue.append(source)
    return paths


def _mismatch(
    paths: dict[str, tuple[str, ...]],
    datasets: dict[str, dict],
    expected_tenant: str,
    expected_region: str,
) -> tuple[str, tuple[str, ...], list[str]] | None:
    candidates = []
    for source, reverse_path in paths.items():
        dimensions = []
        if datasets[source]["tenant_ref"] != expected_tenant:
            dimensions.append("tenant")
        if datasets[source]["region_ref"] != expected_region:
            dimensions.append("region")
        if dimensions:
            path = tuple(reversed(reverse_path))
            candidates.append((len(path), path, source, dimensions))
    if not candidates:
        return None
    _, path, source, dimensions = min(candidates)
    return source, path, dimensions


def _derive(model: Any) -> dict:
    plan = _plan(model)
    datasets = {row["dataset_ref"]: row for row in plan["datasets"]}
    unknown_ids = {
        row["transfer_id"] for row in plan["transfers"] if row["state"] == "unknown"
    }
    findings = []
    for objective in plan["objectives"]:
        output = objective["output_dataset_ref"]
        expected_tenant = objective["expected_tenant_ref"]
        expected_region = objective["expected_region_ref"]
        included = _mismatch(
            _paths(plan, output, include_unknown=False), datasets, expected_tenant,
            expected_region,
        )
        possible = None
        if included is None:
            possible = _mismatch(
                _paths(plan, output, include_unknown=True), datasets, expected_tenant,
                expected_region,
            )
        witness = included or possible
        if included is not None:
            disposition = "declared_lineage_boundary_mismatch"
        elif possible is not None:
            disposition = "unknown_transfer_policy"
        else:
            disposition = (
                "no_supplied_mismatch"
                if plan["lineage_complete"]
                else "unknown_incomplete_lineage"
            )
        source, path, dimensions = witness if witness is not None else (None, (), [])
        findings.append(
            {
                "output_dataset_ref": output,
                "expected_tenant_ref": expected_tenant,
                "expected_region_ref": expected_region,
                "disposition": disposition,
                "source_dataset_ref": source,
                "mismatched_dimensions": dimensions,
                "transfer_ids": list(path),
                "unknown_transfer_ids": [item for item in path if item in unknown_ids],
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "findings": findings,
        "flags": {
            "dataset_identity_verified": False,
            "transfer_policy_verified": False,
            "data_movement_observed": False,
            "residency_violation_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Dataset tags, transfer declarations, and completeness are caller-supplied.",
            "The selected witness is a shortest declared source path, not data-flow proof.",
            "A tenant or region mismatch does not prove exposure or a residency violation.",
            "No warehouse, lake, query, provider, credential, network, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "WHL-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class WarehouseLineage:
    """Immutable report replayed from supplied dataset transfer declarations."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise WarehouseLineageError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise WarehouseLineageError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_warehouse_lineage(model: Any) -> WarehouseLineage:
    """Project declared warehouse or lake lineage without target interaction."""
    return WarehouseLineage(_derive(model))


def verify_supplied_warehouse_lineage(
    report: Any, *, model: Any
) -> WarehouseLineage:
    if type(report) is not WarehouseLineage:
        raise WarehouseLineageError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise WarehouseLineageError("Report differs from supplied model replay")
    return WarehouseLineage(expected)
