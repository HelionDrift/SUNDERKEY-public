"""Compare synthetic eBPF helper declarations with supplied program policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "linux_supplied_ebpf_helper_policy_projection"
PROFILE_ID = "AOE-GC-D12-S02"
CAPABILITY_ID = "army.gc.d12.s02"
VECTOR_ID = "AV-GC-D12-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D12-S02"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GC-D12-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:49cbcda979cdb3115ca1611ffe8ac548032e3040f8599862bdccb963d032a4d3"
DOMAIN = "sunderkey.offline-ebpf-helper-policy.v1"
PROGRAM_TYPES = frozenset({"tracing", "network", "security"})
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class EbpfHelperPolicyError(ValueError):
    """A supplied eBPF helper model or replay is invalid."""


def _identifiers(value: Any, *, label: str, limit: int = 32) -> list[str]:
    items = [core.identifier(item, label) for item in core.bounded_list(value, limit, label)]
    if len(items) != len(set(items)):
        raise EbpfHelperPolicyError(f"Duplicate {label}")
    return items


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "helper_policies", "programs",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise EbpfHelperPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise EbpfHelperPolicyError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    policies = {}
    for item in core.bounded_list(model["helper_policies"], 8, "helper policies"):
        row = core.exact(item, {"program_type", "allowed_helper_ids"}, "helper policy")
        kind = core.identifier(row["program_type"], "program type")
        if kind not in PROGRAM_TYPES or kind in policies:
            raise EbpfHelperPolicyError("Duplicate or unknown program type policy")
        policies[kind] = set(_identifiers(row["allowed_helper_ids"], label="helper ID"))
    if not policies:
        raise EbpfHelperPolicyError("At least one helper policy is required")
    programs = core.bounded_list(model["programs"], 64, "programs")
    if not programs:
        raise EbpfHelperPolicyError("At least one program is required")
    rows = []
    seen = set()
    for item in programs:
        row = core.exact(item, {
            "program_id", "program_type", "declared_helper_ids",
        }, "program")
        program_id = core.identifier(row["program_id"], "program ID")
        kind = core.identifier(row["program_type"], "program type")
        if program_id in seen or kind not in policies:
            raise EbpfHelperPolicyError("Duplicate program or missing type policy")
        seen.add(program_id)
        helpers = _identifiers(row["declared_helper_ids"], label="declared helper ID")
        disallowed = sorted(set(helpers) - policies[kind])
        rows.append({
            "program_id": program_id,
            "program_type": kind,
            "declared_helper_ids": sorted(helpers),
            "outside_supplied_policy_helper_ids": disallowed,
        })
    rows.sort(key=lambda row: row["program_id"])
    deviations = [row["program_id"] for row in rows if row["outside_supplied_policy_helper_ids"]]
    unknown = [] if complete else ["supplied_ebpf_program_inventory_incomplete"]
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
        "program_projections": rows,
        "declared_policy_deviation_program_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_ebpf_helper_projection",
        "source_authenticated": False,
        "kernel_connected": False,
        "bytecode_parsed": False,
        "verifier_invoked": False,
        "program_loaded": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Program types, helper IDs, policies, and completeness are assertions.",
            "The model does not parse bytecode or run the kernel verifier.",
            "A policy mismatch does not establish eBPF exploitability or execution.",
            "No kernel, program, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="EHP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class EbpfHelperPolicyReport:
    """Unsigned helper projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise EbpfHelperPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> EbpfHelperPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_ebpf_helpers(model: Any) -> EbpfHelperPolicyReport:
    return EbpfHelperPolicyReport._owned(_derive(model))


def verify_supplied_ebpf_helpers(report: Any, *, model: Any) -> EbpfHelperPolicyReport:
    if type(report) is not EbpfHelperPolicyReport:
        raise EbpfHelperPolicyError("Exact eBPF helper wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise EbpfHelperPolicyError("Report differs from separate original model")
    return EbpfHelperPolicyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-ebpf-helpers",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "helper_policies": [{
            "program_type": "tracing", "allowed_helper_ids": ["helper-a"],
        }],
        "programs": [{
            "program_id": "program-a", "program_type": "tracing",
            "declared_helper_ids": ["helper-a", "helper-b"],
        }],
    }
