"""Project supplied RISC-V PMP intervals for S and U mode accesses."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "riscv_supplied_pmp_interval_projection"
PROFILE_ID = "AOE-GD-D24-S07"
CAPABILITY_ID = "army.gd.d24.s07"
VECTOR_ID = "AV-GD-D24-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D24-S07"
WAVE_ID = "IW2-007"
COMMANDER_ID = "AOE-GD-D24-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:3f6413da9a0ab5c3a1350f4c2cff71494c6662fcbbb55acbfa0217cb795f0d49"
DOMAIN = "sunderkey.offline-riscv-pmp-projection.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_ADDRESS = 1 << 48
OPERATIONS = {"read", "write", "execute"}
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class RiscvPmpProjectionError(ValueError):
    """A supplied PMP interval model or original replay is invalid."""


def _integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RiscvPmpProjectionError(f"{label} is out of bounds")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "entries_complete", "entries", "accesses"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise RiscvPmpProjectionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["entries_complete"], "entry completeness")
    entries = core.bounded_list(model["entries"], 64, "PMP entries")
    accesses = core.bounded_list(model["accesses"], 64, "accesses")
    if not entries or not accesses:
        raise RiscvPmpProjectionError("Entries and accesses must be nonempty")
    entry_ids: set[str] = set()
    priorities: set[int] = set()
    for item in entries:
        row = core.exact(
            item,
            {"entry_id", "priority", "range_start", "range_end_exclusive", "permissions"},
            "PMP entry",
        )
        entry_id = core.identifier(row["entry_id"], "entry ID")
        priority = _integer(row["priority"], "priority", minimum=0, maximum=63)
        start = _integer(row["range_start"], "range start", minimum=0, maximum=MAX_ADDRESS - 1)
        end = _integer(
            row["range_end_exclusive"], "range end", minimum=1, maximum=MAX_ADDRESS
        )
        if start >= end:
            raise RiscvPmpProjectionError("PMP interval must be nonempty")
        permissions = core.bounded_list(row["permissions"], 3, "permissions")
        if any(
            type(permission) is not str or permission not in OPERATIONS
            for permission in permissions
        ):
            raise RiscvPmpProjectionError("Unsupported permission")
        if len(permissions) != len(set(permissions)):
            raise RiscvPmpProjectionError("Duplicate permission")
        if entry_id in entry_ids or priority in priorities:
            raise RiscvPmpProjectionError("Duplicate entry ID or priority")
        entry_ids.add(entry_id)
        priorities.add(priority)
    access_ids: set[str] = set()
    for item in accesses:
        row = core.exact(
            item,
            {"access_id", "address", "byte_count", "mode", "operation", "expected_decision"},
            "access",
        )
        access_id = core.identifier(row["access_id"], "access ID")
        address = _integer(row["address"], "address", minimum=0, maximum=MAX_ADDRESS - 1)
        byte_count = _integer(row["byte_count"], "byte count", minimum=1, maximum=4_096)
        if address + byte_count > MAX_ADDRESS:
            raise RiscvPmpProjectionError("Access exceeds modeled physical address space")
        if type(row["mode"]) is not str or row["mode"] not in ("S", "U"):
            raise RiscvPmpProjectionError("Only S and U modes are modeled")
        if type(row["operation"]) is not str or row["operation"] not in OPERATIONS:
            raise RiscvPmpProjectionError("Unsupported access operation")
        if (
            type(row["expected_decision"]) is not str
            or row["expected_decision"] not in ("allow", "deny")
        ):
            raise RiscvPmpProjectionError("Unsupported expected decision")
        if access_id in access_ids:
            raise RiscvPmpProjectionError("Duplicate access ID")
        access_ids.add(access_id)
    return model, core.canonical(model)


def _project(access: dict, entries: list[dict]) -> tuple[str, str | None]:
    start = access["address"]
    end = start + access["byte_count"]
    for entry in entries:
        if entry["range_start"] < end and start < entry["range_end_exclusive"]:
            full_match = entry["range_start"] <= start and end <= entry["range_end_exclusive"]
            decision = (
                "allow"
                if full_match and access["operation"] in entry["permissions"]
                else "deny"
            )
            return decision, entry["entry_id"]
    return "deny", None


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    entries = sorted(model["entries"], key=lambda row: row["priority"])
    decisions = []
    mismatches = []
    for access in model["accesses"]:
        decision, entry_id = _project(access, entries)
        row = {
            "access_id": access["access_id"],
            "computed_decision": decision,
            "expected_decision": access["expected_decision"],
            "matched_entry_id": entry_id,
        }
        decisions.append(row)
        if decision != access["expected_decision"]:
            mismatches.append({
                "access_id": access["access_id"],
                "issue": "unexpected_allow" if decision == "allow" else "unexpected_deny",
            })
    disposition = (
        "unknown"
        if not model["entries_complete"]
        else "candidate_supplied_pmp_decision_mismatch"
        if mismatches
        else "supplied_pmp_decisions_match"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "entry_count": len(entries),
        "access_count": len(model["accesses"]),
        "decisions": decisions,
        "mismatches": mismatches,
        "disposition": disposition,
        "candidate_count": len(mismatches) if model["entries_complete"] else 0,
        "unknown_count": int(not model["entries_complete"]),
        "source_authenticated": False,
        "soc_contacted": False,
        "csr_encoding_verified": False,
        "hardware_decision_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "PMP entries are supplied as predecoded intervals, not CSR encodings.",
            "Only S/U accesses are modeled; M mode, Smepmp, PMA and translation are excluded.",
            "Entry completeness, access expectations and device behavior are unverified.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PMP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class RiscvPmpProjectionReport:
    """Unsigned PMP projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise RiscvPmpProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> RiscvPmpProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_riscv_pmp(model: Any) -> RiscvPmpProjectionReport:
    return RiscvPmpProjectionReport._owned(_derive(model))


def verify_supplied_riscv_pmp(report: Any, *, model: Any) -> RiscvPmpProjectionReport:
    if type(report) is not RiscvPmpProjectionReport:
        raise RiscvPmpProjectionError("Exact PMP wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise RiscvPmpProjectionError("Report differs from separate original model")
    return RiscvPmpProjectionReport._owned(expected)


def verify_supplied_riscv_pmp_bytes(
    report_bytes: bytes, *, model: Any
) -> RiscvPmpProjectionReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise RiscvPmpProjectionError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise RiscvPmpProjectionError("Exported report differs from original replay")
    return RiscvPmpProjectionReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-pmp-intervals",
        "entries_complete": True,
        "entries": [
            {
                "entry_id": "pmp0",
                "priority": 0,
                "range_start": 4096,
                "range_end_exclusive": 8192,
                "permissions": ["read", "write"],
            }
        ],
        "accesses": [
            {
                "access_id": "write-a",
                "address": 4352,
                "byte_count": 4,
                "mode": "S",
                "operation": "write",
                "expected_decision": "deny",
            }
        ],
    }
