"""Compare supplied linear proxy storage layouts at byte intervals."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "evm_supplied_proxy_storage_layout"
PROFILE_ID = "AOE-GB-D10-S07"
CAPABILITY_ID = "army.gb.d10.s07"
VECTOR_ID = "AV-GB-D10-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D10-S07"
WAVE_ID = "IW2-007"
COMMANDER_ID = "AOE-GB-D10-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:767edb047cee30f535e730cd2661fdad7793a1cd0799759183c542ea771e3465"
DOMAIN = "sunderkey.offline-proxy-storage-layout.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "execution",
        "filesystem",
        "network",
        "process",
        "provider",
        "credentials",
        "target_interaction",
        "finding_publication",
        "qualification",
    )
}


class ProxyStorageLayoutError(ValueError):
    """A supplied linear storage layout or replay is invalid."""


def _fields(value: Any, label: str) -> list[dict]:
    rows = core.bounded_list(value, 64, label)
    if not rows:
        raise ProxyStorageLayoutError(f"{label} must not be empty")
    seen: set[str] = set()
    occupied: set[tuple[int, int]] = set()
    for item in rows:
        row = core.exact(
            item,
            {"field_id", "slot", "offset_bytes", "size_bytes", "type_sha256"},
            label,
        )
        field_id = core.identifier(row["field_id"], "field ID")
        if field_id in seen:
            raise ProxyStorageLayoutError("Duplicate field ID")
        seen.add(field_id)
        slot, offset, size = (row[key] for key in ("slot", "offset_bytes", "size_bytes"))
        if type(slot) is not int or not 0 <= slot <= 1_000_000:
            raise ProxyStorageLayoutError("Slot must be a bounded linear index")
        if type(offset) is not int or not 0 <= offset < 32:
            raise ProxyStorageLayoutError("Offset must be within one storage slot")
        if type(size) is not int or not 1 <= size <= 32 or offset + size > 32:
            raise ProxyStorageLayoutError("Field must fit inside one storage slot")
        digest = row["type_sha256"]
        if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
            raise ProxyStorageLayoutError("Semantic type digest must be lowercase SHA-256")
        positions = {(slot, byte) for byte in range(offset, offset + size)}
        if occupied & positions:
            raise ProxyStorageLayoutError("Fields overlap within one declared layout")
        occupied.update(positions)
    return rows


def _model(value: Any) -> tuple[dict, str, list[dict], list[dict]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version",
            "source_id",
            "prior_contract_id",
            "next_contract_id",
            "layout_family",
            "declaration_complete",
            "prior_fields",
            "next_fields",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ProxyStorageLayoutError("Unsupported model version")
    for key in ("source_id", "prior_contract_id", "next_contract_id"):
        core.identifier(model[key], key)
    if model["prior_contract_id"] == model["next_contract_id"]:
        raise ProxyStorageLayoutError("Contract revision identifiers must differ")
    core.choice(model["layout_family"], {"linear_slot_map"}, "layout family")
    core.boolean(model["declaration_complete"], "declaration completeness")
    prior = _fields(model["prior_fields"], "prior fields")
    following = _fields(model["next_fields"], "next fields")
    return model, core.canonical(model), prior, following


def _positions(field: dict) -> set[tuple[int, int]]:
    return {
        (field["slot"], byte)
        for byte in range(field["offset_bytes"], field["offset_bytes"] + field["size_bytes"])
    }


def _derive(value: Any) -> dict:
    model, model_text, prior, following = _model(value)
    prior_by_id = {row["field_id"]: row for row in prior}
    next_by_id = {row["field_id"]: row for row in following}
    prior_occupied = set().union(*(_positions(row) for row in prior))
    projections = []
    for field_id in sorted(prior_by_id):
        earlier = prior_by_id[field_id]
        later = next_by_id.get(field_id)
        if later is None:
            status = "unknown_removed_prior_field"
        elif any(
            earlier[key] != later[key]
            for key in ("slot", "offset_bytes", "size_bytes", "type_sha256")
        ):
            status = "candidate_declared_prior_field_reinterpreted"
        else:
            status = "declared_prior_field_preserved"
        if not model["declaration_complete"]:
            status = "unknown"
        projections.append({"field_id": field_id, "relation": "prior", "disposition": status})
    for field_id in sorted(set(next_by_id) - set(prior_by_id)):
        later = next_by_id[field_id]
        status = (
            "candidate_declared_new_field_overlap"
            if _positions(later) & prior_occupied
            else "new_field_without_declared_overlap"
        )
        if not model["declaration_complete"]:
            status = "unknown"
        projections.append({"field_id": field_id, "relation": "new", "disposition": status})
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "prior_field_count": len(prior),
        "next_field_count": len(following),
        "field_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"].startswith("unknown") for row in projections),
        "source_authenticated": False,
        "compiler_invoked": False,
        "contract_executed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Layout positions, stable field IDs and normalized semantic type digests are supplied.",
            "Only linear single-slot fields are compared; other layouts are omitted.",
            "A removed field is unknown because reserved storage may preserve compatibility.",
            "A collision candidate does not prove deployment, exploitability or value corruption.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PSL-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class ProxyStorageLayoutReport:
    """Unsigned byte-layout projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ProxyStorageLayoutError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ProxyStorageLayoutReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_proxy_storage_layout(model: Any) -> ProxyStorageLayoutReport:
    return ProxyStorageLayoutReport._owned(_derive(model))


def verify_supplied_proxy_storage_layout(report: Any, *, model: Any) -> ProxyStorageLayoutReport:
    if type(report) is not ProxyStorageLayoutReport:
        raise ProxyStorageLayoutError("Exact storage-layout wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ProxyStorageLayoutError("Report differs from separate original model")
    return ProxyStorageLayoutReport._owned(expected)


def verify_supplied_proxy_storage_layout_bytes(
    report_bytes: bytes, *, model: Any
) -> ProxyStorageLayoutReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise ProxyStorageLayoutError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise ProxyStorageLayoutError("Exported report differs from original replay")
    return ProxyStorageLayoutReport._owned(expected)


def component_fixture() -> dict:
    digest = "sha256:" + "1" * 64
    return {
        "schema_version": 1,
        "source_id": "synthetic-storage-layout",
        "prior_contract_id": "revision-one",
        "next_contract_id": "revision-two",
        "layout_family": "linear_slot_map",
        "declaration_complete": True,
        "prior_fields": [
            {
                "field_id": "owner",
                "slot": 0,
                "offset_bytes": 0,
                "size_bytes": 20,
                "type_sha256": digest,
            },
            {
                "field_id": "balance",
                "slot": 1,
                "offset_bytes": 0,
                "size_bytes": 32,
                "type_sha256": digest,
            },
        ],
        "next_fields": [
            {
                "field_id": "owner",
                "slot": 0,
                "offset_bytes": 0,
                "size_bytes": 20,
                "type_sha256": digest,
            },
            {
                "field_id": "balance",
                "slot": 2,
                "offset_bytes": 0,
                "size_bytes": 32,
                "type_sha256": digest,
            },
            {
                "field_id": "nonce",
                "slot": 1,
                "offset_bytes": 0,
                "size_bytes": 8,
                "type_sha256": digest,
            },
        ],
    }
