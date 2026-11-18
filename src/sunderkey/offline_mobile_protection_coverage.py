"""Project synthetic anti-tamper coverage across declared mobile build variants."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "mobile_supplied_protection_coverage_projection"
PROFILE_ID = "AOE-GB-D08-S11"
CAPABILITY_ID = "army.gb.d08.s11"
VECTOR_ID = "AV-GB-D08-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D08-S11"
WAVE_ID = "IW2-015"
COMMANDER_ID = "AOE-GB-D08-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:75e8f5c5baeb408dfc9355a519504907c862b0fd83ebeb39dedb97aef250e7df"
DOMAIN = "sunderkey.offline-mobile-protection-coverage.v1"
KINDS = {"obfuscation", "integrity_check", "debug_detection", "runtime_attestation"}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class MobileProtectionCoverageError(ValueError):
    """The supplied declaration or original-model replay is invalid."""


def _unique_ids(value: Any, maximum: int, label: str) -> list[str]:
    items = [core.identifier(item, label) for item in core.bounded_list(value, maximum, label)]
    if not items or len(items) != len(set(items)):
        raise MobileProtectionCoverageError(f"{label} must be nonempty and unique")
    return items


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "variant_ids", "modules", "protections",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MobileProtectionCoverageError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise MobileProtectionCoverageError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    variants = _unique_ids(model["variant_ids"], 16, "variant IDs")
    modules = {}
    for item in core.bounded_list(model["modules"], 32, "modules"):
        row = core.exact(item, {"module_id", "required_kinds"}, "module")
        module_id = core.identifier(row["module_id"], "module ID")
        if module_id in modules:
            raise MobileProtectionCoverageError("Duplicate module ID")
        kinds = [
            core.choice(kind, KINDS, "required protection kind")
            for kind in core.bounded_list(row["required_kinds"], 4, "required kinds")
        ]
        if len(kinds) != len(set(kinds)):
            raise MobileProtectionCoverageError("Duplicate required protection kind")
        modules[module_id] = set(kinds)
    if not modules:
        raise MobileProtectionCoverageError("At least one module is required")
    coverage: dict[tuple[str, str], set[str]] = {
        (variant, module_id): set() for variant in variants for module_id in modules
    }
    seen_protections = set()
    for item in core.bounded_list(model["protections"], 64, "protections"):
        row = core.exact(item, {
            "protection_id", "kind", "module_ids", "variant_ids",
        }, "protection")
        protection_id = core.identifier(row["protection_id"], "protection ID")
        if protection_id in seen_protections:
            raise MobileProtectionCoverageError("Duplicate protection ID")
        seen_protections.add(protection_id)
        kind = core.choice(row["kind"], KINDS, "protection kind")
        module_ids = _unique_ids(row["module_ids"], 32, "covered module IDs")
        variant_ids = _unique_ids(row["variant_ids"], 16, "covered variant IDs")
        if any(module_id not in modules for module_id in module_ids):
            raise MobileProtectionCoverageError("Unknown covered module")
        if any(variant not in variants for variant in variant_ids):
            raise MobileProtectionCoverageError("Unknown covered variant")
        for variant in variant_ids:
            for module_id in module_ids:
                coverage[(variant, module_id)].add(kind)
    gaps = [
        {
            "variant_id": variant,
            "module_id": module_id,
            "missing_declared_protection_kinds": sorted(required - coverage[(variant, module_id)]),
        }
        for variant in sorted(variants)
        for module_id, required in sorted(modules.items())
        if required - coverage[(variant, module_id)]
    ]
    unknown = [] if complete else ["supplied_protection_inventory_incomplete"]
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
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "inventory_complete_asserted": complete,
        "supplied_variant_count": len(variants),
        "supplied_module_count": len(modules),
        "supplied_protection_count": len(seen_protections),
        "declared_coverage_gaps": gaps,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_protection_coverage_projection",
        "source_authenticated": False,
        "application_inspected": False,
        "binary_analyzed": False,
        "protection_effectiveness_verified": False,
        "tamper_attempt_performed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Variants, modules, requirements, and protection coverage are supplied assertions.",
            "A declared gap is a planning mismatch, not evidence of a bypass or vulnerability.",
            "No binary, device, app, anti-tamper control, or target is inspected or exercised.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MPC-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class MobileProtectionCoverageReport:
    """Unsigned projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MobileProtectionCoverageError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MobileProtectionCoverageReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_mobile_protection(model: Any) -> MobileProtectionCoverageReport:
    return MobileProtectionCoverageReport._owned(_derive(model))


def verify_supplied_mobile_protection(
    report: Any, *, model: Any
) -> MobileProtectionCoverageReport:
    if type(report) is not MobileProtectionCoverageReport:
        raise MobileProtectionCoverageError("Exact protection wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MobileProtectionCoverageError("Report differs from separate original model")
    return MobileProtectionCoverageReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-mobile-protection",
        "synthetic_fixture": True, "inventory_complete": True,
        "variant_ids": ["debug", "release"],
        "modules": [{
            "module_id": "payment", "required_kinds": ["obfuscation", "integrity_check"],
        }],
        "protections": [{
            "protection_id": "obfuscate-payment", "kind": "obfuscation",
            "module_ids": ["payment"], "variant_ids": ["release"],
        }],
    }
