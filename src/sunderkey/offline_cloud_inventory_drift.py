"""Compare two supplied cloud inventory snapshots without provider access."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_cloud_inventory_drift"
PROFILE_ID = "AOE-GA-D01-S05"
CAPABILITY_ID = "army.ga.d01.s05"
VECTOR_ID = "AV-GA-D01-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D01-S05"
WAVE_ID = "IW2-005"
COMMANDER_ID = "AOE-GA-D01-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:fffb3e1cd5503fed2f788d99da49b9a3716bc6e1696ec7310b13ecf7857e8625"
SEMANTICS_PROFILE = "supplied-cloud-inventory-drift-v1"
DOMAIN = "sunderkey.offline-cloud-inventory-drift.v1"
MAX_RECORDS_PER_SNAPSHOT = 512
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 20_000
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_PROVIDERS = frozenset({"aws", "azure", "gcp"})
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "cloud_api",
        "credential",
        "execution",
        "filesystem",
        "network",
        "provider",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class CloudInventoryDriftError(ValueError):
    """A supplied snapshot or replay document failed validation."""


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise CloudInventoryDriftError(f"{label} fields are invalid")


def _identifier(value: Any, label: str) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise CloudInventoryDriftError(f"{label} identifier is invalid")


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise CloudInventoryDriftError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise CloudInventoryDriftError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise CloudInventoryDriftError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise CloudInventoryDriftError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise CloudInventoryDriftError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise CloudInventoryDriftError("Native JSON text keys are required")
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
        raise CloudInventoryDriftError("Document byte bound exceeded")
    return encoded


def _plan(model: Any) -> tuple[dict, list[dict], list[dict]]:
    _fields(model, {"schema_version", "semantics_profile", "snapshots"}, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CloudInventoryDriftError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise CloudInventoryDriftError("Semantics profile is invalid")
    snapshots = model["snapshots"]
    if type(snapshots) is not list or len(snapshots) != 2:
        raise CloudInventoryDriftError("Exactly two ordered snapshots are required")
    record_sets: list[list[dict]] = []
    snapshot_ids: set[str] = set()
    for snapshot in snapshots:
        _fields(snapshot, {"snapshot_id", "records"}, "snapshot")
        _identifier(snapshot["snapshot_id"], "snapshot")
        if snapshot["snapshot_id"] in snapshot_ids:
            raise CloudInventoryDriftError("Duplicate snapshot identifier")
        snapshot_ids.add(snapshot["snapshot_id"])
        records = snapshot["records"]
        if type(records) is not list or len(records) > MAX_RECORDS_PER_SNAPSHOT:
            raise CloudInventoryDriftError("Snapshot record count is invalid")
        record_ids: set[str] = set()
        signatures: set[tuple[str, str, str, str]] = set()
        for record in records:
            _fields(
                record,
                {
                    "record_id",
                    "provider",
                    "scope_id",
                    "resource_id",
                    "resource_type",
                    "region",
                    "source_id",
                },
                "record",
            )
            for field in (
                "record_id",
                "scope_id",
                "resource_id",
                "resource_type",
                "region",
                "source_id",
            ):
                _identifier(record[field], field)
            if type(record["provider"]) is not str or record["provider"] not in _PROVIDERS:
                raise CloudInventoryDriftError("Provider is invalid")
            signature = (
                record["provider"],
                record["scope_id"],
                record["resource_id"],
                record["source_id"],
            )
            if record["record_id"] in record_ids or signature in signatures:
                raise CloudInventoryDriftError("Duplicate supplied inventory record")
            record_ids.add(record["record_id"])
            signatures.add(signature)
        record_sets.append(records)
    return json.loads(_canonical(model)), record_sets[0], record_sets[1]


def _groups(records: list[dict]) -> dict[tuple[str, str, str], list[dict]]:
    groups: dict[tuple[str, str, str], list[dict]] = {}
    for record in records:
        key = (record["provider"], record["scope_id"], record["resource_id"])
        groups.setdefault(key, []).append(record)
    return groups


def _claims(records: list[dict]) -> list[dict]:
    return [
        {"resource_type": kind, "region": region}
        for kind, region in sorted({(item["resource_type"], item["region"]) for item in records})
    ]


def _derive(model: Any) -> dict:
    plan, earlier, later = _plan(model)
    earlier_groups = _groups(earlier)
    later_groups = _groups(later)
    observations = []
    for key in sorted(earlier_groups.keys() | later_groups.keys()):
        before = earlier_groups.get(key, [])
        after = later_groups.get(key, [])
        before_claims = _claims(before)
        after_claims = _claims(after)
        if len(after_claims) > 1:
            state = "conflicted_supplied_latest"
        elif len(before_claims) > 1:
            state = "incomparable_prior_conflict"
        elif not before:
            state = "new_in_supplied_latest"
        elif not after:
            state = "not_observed_in_supplied_latest"
        elif before_claims == after_claims:
            state = "unchanged_supplied_claim"
        else:
            state = "changed_supplied_claim"
        observations.append(
            {
                "provider": key[0],
                "scope_id": key[1],
                "resource_id": key[2],
                "state": state,
                "earlier_claims": before_claims,
                "later_claims": after_claims,
                "earlier_record_ids": sorted(item["record_id"] for item in before),
                "later_record_ids": sorted(item["record_id"] for item in after),
                "earlier_source_ids": sorted({item["source_id"] for item in before}),
                "later_source_ids": sorted({item["source_id"] for item in after}),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "observations": observations,
        "flags": {
            "snapshot_sources_authenticated": False,
            "snapshot_completeness_proven": False,
            "provider_resource_existence_proven": False,
            "provider_resource_deletion_proven": False,
            "scope_ownership_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Both ordered snapshots and every identity claim are caller-supplied.",
            "Opaque resource identifiers are compared exactly, not provider-validated.",
            "A missing row does not prove that a provider resource was deleted.",
            "No cloud account, provider API, credential or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "CID-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class CloudInventoryDriftAnalysis:
    """Replay-checked supplied snapshot comparison without cloud access."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise CloudInventoryDriftError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise CloudInventoryDriftError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_cloud_inventory_drift(model: Any) -> CloudInventoryDriftAnalysis:
    """Compare two supplied snapshots without implying actual cloud drift."""
    return CloudInventoryDriftAnalysis(_derive(model))


def verify_supplied_cloud_inventory_drift(
    report: Any, *, model: Any
) -> CloudInventoryDriftAnalysis:
    """Independently rederive the supplied result from a current native model."""
    if type(report) is not CloudInventoryDriftAnalysis:
        raise CloudInventoryDriftError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise CloudInventoryDriftError("Report differs from supplied model replay")
    return CloudInventoryDriftAnalysis(expected)


__all__ = [
    "COMPONENT_ID",
    "PROFILE_ID",
    "CloudInventoryDriftAnalysis",
    "CloudInventoryDriftError",
    "analyze_supplied_cloud_inventory_drift",
    "verify_supplied_cloud_inventory_drift",
]
