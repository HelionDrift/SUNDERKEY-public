"""Project synthetic BSD and Unix privileged IPC permission declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "unix_supplied_privileged_ipc_permission_projection"
PROFILE_ID = "AOE-GC-D12-S14"
CAPABILITY_ID = "army.gc.d12.s14"
VECTOR_ID = "AV-GC-D12-S14-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D12-S14"
WAVE_ID = "IW2-014"
COMMANDER_ID = "AOE-GC-D12-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:cf2529c6ab0d4f59807beec825365dc6caca99f318e1dcf9521aa786f530cbb6"
DOMAIN = "sunderkey.offline-unix-ipc-permissions.v1"
ARTIFACT_KINDS = frozenset({"unix_socket", "named_pipe"})
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class UnixIpcPermissionError(ValueError):
    """A supplied Unix IPC permission model or replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "artifacts",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise UnixIpcPermissionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise UnixIpcPermissionError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    artifacts = core.bounded_list(model["artifacts"], 64, "artifacts")
    if not artifacts:
        raise UnixIpcPermissionError("At least one artifact is required")
    rows = []
    seen = set()
    for item in artifacts:
        row = core.exact(item, {
            "artifact_id", "artifact_kind", "privileged_service_declared",
            "world_writable_declared",
        }, "artifact")
        artifact_id = core.identifier(row["artifact_id"], "artifact ID")
        kind = core.identifier(row["artifact_kind"], "artifact kind")
        if artifact_id in seen or kind not in ARTIFACT_KINDS:
            raise UnixIpcPermissionError("Duplicate artifact or unknown kind")
        seen.add(artifact_id)
        privileged = core.boolean(
            row["privileged_service_declared"], "privileged service declaration"
        )
        writable = core.boolean(row["world_writable_declared"], "world write declaration")
        flags = ["declared_privileged_world_write_overlap"] if privileged and writable else []
        rows.append({
            "artifact_id": artifact_id,
            "artifact_kind": kind,
            "privileged_service_declared": privileged,
            "world_writable_declared": writable,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["artifact_id"])
    deviations = [row["artifact_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_unix_ipc_inventory_incomplete"]
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
        "artifact_projections": rows,
        "declared_policy_deviation_artifact_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_unix_ipc_projection",
        "source_authenticated": False,
        "host_connected": False,
        "permissions_verified": False,
        "ipc_connected": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Artifact kinds, service privilege, permissions, and completeness are assertions.",
            "The model does not inspect BSD or Unix IPC permissions.",
            "A declared overlap does not prove unauthorized access or impact.",
            "No host, socket, pipe, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="UIP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class UnixIpcPermissionReport:
    """Unsigned IPC permission projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise UnixIpcPermissionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> UnixIpcPermissionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_unix_ipc(model: Any) -> UnixIpcPermissionReport:
    return UnixIpcPermissionReport._owned(_derive(model))


def verify_supplied_unix_ipc(report: Any, *, model: Any) -> UnixIpcPermissionReport:
    if type(report) is not UnixIpcPermissionReport:
        raise UnixIpcPermissionError("Exact Unix IPC wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise UnixIpcPermissionError("Report differs from separate original model")
    return UnixIpcPermissionReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-unix-ipc",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "artifacts": [{
            "artifact_id": "socket-a", "artifact_kind": "unix_socket",
            "privileged_service_declared": True, "world_writable_declared": True,
        }],
    }
