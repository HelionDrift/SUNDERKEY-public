"""Project supplied hybrid key-material lineage without processing keys."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "crypto_supplied_hybrid_kem_lineage"
PROFILE_ID = "AOE-GE-D22-S07"
CAPABILITY_ID = "army.ge.d22.s07"
VECTOR_ID = "AV-GE-D22-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D22-S07"
WAVE_ID = "IW2-020"
COMMANDER_ID = "AOE-GE-D22-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:36ad2bfc96e5ab6c864ee71646dfaa4759a8b094d0cfa1af98e2de5e888a65a2"
DOMAIN = "sunderkey.offline-hybrid-kem-lineage.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_CONTRIBUTIONS = 32
MAX_DERIVATIONS = 32
MAX_INPUTS = 8
REQUIRED_KINDS = {"classical", "post_quantum"}
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class HybridKemLineageError(ValueError):
    """The supplied lineage or its original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, dict[str, str], dict[str, tuple[str, ...]], str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "material_inventory_complete",
            "final_material_id", "contributions", "derivations",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise HybridKemLineageError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["material_inventory_complete"], "inventory completeness")
    final = core.identifier(model["final_material_id"], "final material ID")
    contributions = {}
    for item in core.bounded_list(model["contributions"], MAX_CONTRIBUTIONS, "contributions"):
        row = core.exact(item, {"material_id", "kind"}, "contribution")
        material = core.identifier(row["material_id"], "material ID")
        if material in contributions:
            raise HybridKemLineageError("Duplicate contribution ID")
        contributions[material] = core.choice(row["kind"], REQUIRED_KINDS, "kind")
    if not contributions:
        raise HybridKemLineageError("At least one contribution is required")
    derivations = {}
    for item in core.bounded_list(model["derivations"], MAX_DERIVATIONS, "derivations"):
        row = core.exact(item, {"material_id", "input_material_ids"}, "derivation")
        material = core.identifier(row["material_id"], "material ID")
        if material in contributions or material in derivations:
            raise HybridKemLineageError("Duplicate material ID")
        inputs = tuple(
            core.identifier(source, "input material ID")
            for source in core.bounded_list(
                row["input_material_ids"], MAX_INPUTS, "derivation inputs"
            )
        )
        if not inputs or len(inputs) != len(set(inputs)) or material in inputs:
            raise HybridKemLineageError("Derivation inputs must be nonempty, unique and not self")
        derivations[material] = tuple(sorted(inputs))
    if final not in derivations:
        raise HybridKemLineageError("Final material must be a supplied derivation")
    inventory = set(contributions) | set(derivations)
    if any(not set(inputs).issubset(inventory) for inputs in derivations.values()):
        raise HybridKemLineageError("Input material is outside supplied inventory")
    return model, contributions, derivations, core.canonical(model)


def _derive(value: Any) -> dict:
    model, contributions, derivations, source_text = _model(value)
    pending = set(derivations)
    sources: dict[str, set[str]] = {material: {material} for material in contributions}
    while pending:
        ready = sorted(
            material for material in pending
            if set(derivations[material]).issubset(sources)
        )
        if not ready:
            raise HybridKemLineageError("Material derivation cycle")
        for material in ready:
            sources[material] = set().union(
                *(sources[input_id] for input_id in derivations[material])
            )
        pending.difference_update(ready)
    final_sources = sources[model["final_material_id"]]
    kinds = {contributions[material] for material in final_sources}
    unknown = [] if model["material_inventory_complete"] else [
        "supplied_material_inventory_incomplete"
    ]
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "group_owner_id": GROUP_OWNER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "material_inventory_complete_asserted": model["material_inventory_complete"],
        "supplied_contribution_count": len(contributions),
        "supplied_derivation_count": len(derivations),
        "final_material_id": model["final_material_id"],
        "final_source_contribution_ids": sorted(final_sources),
        "final_source_kinds": sorted(kinds),
        "missing_hybrid_source_kinds": sorted(REQUIRED_KINDS - kinds),
        "structural_disposition": (
            "both_kinds_declared" if kinds == REQUIRED_KINDS else "single_kind_declared"
        ),
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_material_lineage_projection",
        "source_authenticated": False,
        "key_material_read": False,
        "kem_operation_performed": False,
        "combiner_security_verified": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Contribution kinds and derivation edges are caller-supplied assertions.",
            "Both declared kinds reaching one node does not validate a hybrid KEM combiner.",
            "No key material, algorithm, handshake, endpoint or target is inspected.",
            "The projection grants no finding, qualification or action authority.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="HKL-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class HybridKemLineageReport:
    """Unsigned lineage projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise HybridKemLineageError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> HybridKemLineageReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_hybrid_kem_lineage(model: Any) -> HybridKemLineageReport:
    return HybridKemLineageReport._owned(_derive(model))


def verify_supplied_hybrid_kem_lineage(
    report: Any, *, model: Any
) -> HybridKemLineageReport:
    if type(report) is not HybridKemLineageReport:
        raise HybridKemLineageError("Exact lineage wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise HybridKemLineageError("Report differs from separate original model")
    return HybridKemLineageReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-hybrid-lineage",
        "material_inventory_complete": True,
        "final_material_id": "session",
        "contributions": [
            {"material_id": "traditional", "kind": "classical"},
            {"material_id": "new_scheme", "kind": "post_quantum"},
        ],
        "derivations": [
            {"material_id": "session", "input_material_ids": ["traditional", "new_scheme"]},
        ],
    }
