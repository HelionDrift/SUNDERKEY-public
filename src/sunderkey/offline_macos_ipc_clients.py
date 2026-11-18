"""Compare synthetic XPC and Apple Events clients with supplied policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "macos_supplied_ipc_client_policy_projection"
PROFILE_ID = "AOE-GC-D12-S13"
CAPABILITY_ID = "army.gc.d12.s13"
VECTOR_ID = "AV-GC-D12-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D12-S13"
WAVE_ID = "IW2-013"
COMMANDER_ID = "AOE-GC-D12-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:e504b25e9d5742438aa6818096245c8fa8e9e547b047ca9ad6f51431bbe5f1d2"
DOMAIN = "sunderkey.offline-macos-ipc-clients.v1"
INTERFACE_KINDS = frozenset({"xpc", "apple_event"})
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class MacosIpcClientError(ValueError):
    """A supplied IPC-client model or replay is invalid."""


def _identifiers(value: Any, *, label: str) -> list[str]:
    items = [core.identifier(item, label) for item in core.bounded_list(value, 32, label)]
    if len(items) != len(set(items)):
        raise MacosIpcClientError(f"Duplicate {label}")
    return items


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "interfaces",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MacosIpcClientError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise MacosIpcClientError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    interfaces = core.bounded_list(model["interfaces"], 64, "interfaces")
    if not interfaces:
        raise MacosIpcClientError("At least one interface is required")
    rows = []
    seen = set()
    for item in interfaces:
        row = core.exact(item, {
            "interface_id", "interface_kind", "approved_client_ids",
            "declared_client_ids",
        }, "interface")
        interface_id = core.identifier(row["interface_id"], "interface ID")
        kind = core.identifier(row["interface_kind"], "interface kind")
        if interface_id in seen or kind not in INTERFACE_KINDS:
            raise MacosIpcClientError("Duplicate interface or unknown kind")
        seen.add(interface_id)
        approved = _identifiers(row["approved_client_ids"], label="approved client ID")
        declared = _identifiers(row["declared_client_ids"], label="declared client ID")
        outside = sorted(set(declared) - set(approved))
        rows.append({
            "interface_id": interface_id,
            "interface_kind": kind,
            "approved_client_ids": sorted(approved),
            "declared_client_ids": sorted(declared),
            "outside_supplied_policy_client_ids": outside,
        })
    rows.sort(key=lambda row: row["interface_id"])
    deviations = [row["interface_id"] for row in rows if row["outside_supplied_policy_client_ids"]]
    unknown = [] if complete else ["supplied_ipc_interface_inventory_incomplete"]
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
        "interface_projections": rows,
        "declared_policy_deviation_interface_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_ipc_client_projection",
        "source_authenticated": False,
        "host_connected": False,
        "ipc_interface_connected": False,
        "message_sent": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Interfaces, clients, approvals, and completeness are assertions.",
            "The model does not verify XPC or Apple Events identity enforcement.",
            "A declared client mismatch does not prove unauthorized access.",
            "No IPC message, host, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MIC-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class MacosIpcClientReport:
    """Unsigned IPC-client projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MacosIpcClientError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MacosIpcClientReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_ipc_clients(model: Any) -> MacosIpcClientReport:
    return MacosIpcClientReport._owned(_derive(model))


def verify_supplied_ipc_clients(
    report: Any, *, model: Any
) -> MacosIpcClientReport:
    if type(report) is not MacosIpcClientReport:
        raise MacosIpcClientError("Exact IPC client wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MacosIpcClientError("Report differs from separate original model")
    return MacosIpcClientReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-ipc-clients",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "interfaces": [{
            "interface_id": "service-a", "interface_kind": "xpc",
            "approved_client_ids": ["client-a"],
            "declared_client_ids": ["client-a", "client-b"],
        }],
    }
