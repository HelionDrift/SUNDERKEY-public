"""Check synthetic proposed scan prefixes against supplied scope claims."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "recon_supplied_scan_scope_projection"
PROFILE_ID = "AOE-GA-D01-S02"
CAPABILITY_ID = "army.ga.d01.s02"
VECTOR_ID = "AV-GA-D01-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D01-S02"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GA-D01-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:2b04a1253e4dd59a587685277bf9ac272eaf25871a7fcba20eff9ab2e957d087"
DOMAIN = "sunderkey.offline-scan-scope-projection.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class ScanScopeProjectionError(ValueError):
    """A supplied plan or original-model replay is invalid."""


def _network(value: Any, label: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if type(value) is not str or len(value) > 64:
        raise ScanScopeProjectionError(f"{label} must be a bounded CIDR")
    try:
        parsed = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ScanScopeProjectionError(f"{label} is not a canonical network") from exc
    if str(parsed) != value:
        raise ScanScopeProjectionError(f"{label} must use canonical CIDR notation")
    return parsed


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "supplied_scope_cidrs", "proposals",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ScanScopeProjectionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise ScanScopeProjectionError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    supplied_scopes = core.bounded_list(model["supplied_scope_cidrs"], 32, "scope CIDRs")
    if not supplied_scopes:
        raise ScanScopeProjectionError("At least one supplied scope is required")
    scopes = [_network(item, "supplied scope") for item in supplied_scopes]
    if len(scopes) != len({str(item) for item in scopes}):
        raise ScanScopeProjectionError("Duplicate supplied scope")
    proposals = core.bounded_list(model["proposals"], 64, "proposals")
    if not proposals:
        raise ScanScopeProjectionError("At least one proposal is required")
    rows = []
    seen = set()
    for item in proposals:
        row = core.exact(item, {"proposal_id", "cidr"}, "proposal")
        proposal_id = core.identifier(row["proposal_id"], "proposal ID")
        if proposal_id in seen:
            raise ScanScopeProjectionError("Duplicate proposal ID")
        seen.add(proposal_id)
        proposed = _network(row["cidr"], "proposed CIDR")
        matching = sorted(
            str(scope) for scope in scopes
            if scope.version == proposed.version and proposed.subnet_of(scope)
        )
        rows.append({
            "proposal_id": proposal_id,
            "cidr": str(proposed),
            "ip_version": proposed.version,
            "contained_by_supplied_scope_cidrs": matching,
            "within_supplied_scope": bool(matching),
        })
    rows.sort(key=lambda row: row["proposal_id"])
    outside = [row["proposal_id"] for row in rows if not row["within_supplied_scope"]]
    unknown = [] if complete else ["supplied_scan_scope_inventory_incomplete"]
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
        "supplied_scope_count": len(scopes),
        "proposal_projections": rows,
        "outside_supplied_scope_proposal_ids": outside,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_scan_scope_projection",
        "source_authenticated": False,
        "scope_authorized": False,
        "dns_resolved": False,
        "packet_sent": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Scope, proposed prefixes, and completeness are supplied assertions.",
            "Containment in a supplied CIDR is not authorization to scan it.",
            "DNS, packets, credentials, tools, and targets are not accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SSP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class ScanScopeProjectionReport:
    """Unsigned scope projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ScanScopeProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ScanScopeProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_scan_scopes(model: Any) -> ScanScopeProjectionReport:
    return ScanScopeProjectionReport._owned(_derive(model))


def verify_supplied_scan_scopes(
    report: Any, *, model: Any
) -> ScanScopeProjectionReport:
    if type(report) is not ScanScopeProjectionReport:
        raise ScanScopeProjectionError("Exact scan-scope wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ScanScopeProjectionError("Report differs from separate original model")
    return ScanScopeProjectionReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-scan-plan",
        "synthetic_fixture": True, "inventory_complete": True,
        "supplied_scope_cidrs": ["192.0.2.0/24", "2001:db8::/32"],
        "proposals": [
            {"proposal_id": "within", "cidr": "192.0.2.128/25"},
            {"proposal_id": "outside", "cidr": "198.51.100.0/24"},
        ],
    }
