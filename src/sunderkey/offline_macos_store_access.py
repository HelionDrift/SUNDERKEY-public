"""Compare synthetic Keychain and iCloud access with supplied bindings."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "macos_supplied_store_access_policy_projection"
PROFILE_ID = "AOE-GC-D12-S12"
CAPABILITY_ID = "army.gc.d12.s12"
VECTOR_ID = "AV-GC-D12-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D12-S12"
WAVE_ID = "IW2-012"
COMMANDER_ID = "AOE-GC-D12-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:cb7bbef07673a3a969add739f3e4c481ddd2147632abdc7e5eec7f24f9f65c94"
DOMAIN = "sunderkey.offline-macos-store-access.v1"
STORE_KINDS = frozenset({"keychain", "icloud"})
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class MacosStoreAccessError(ValueError):
    """A supplied store-access model or replay is invalid."""


def _binding(item: Any, *, label: str) -> tuple[str, str]:
    row = core.exact(item, {"app_id", "store_kind"}, label)
    app_id = core.identifier(row["app_id"], "app ID")
    store_kind = core.identifier(row["store_kind"], "store kind")
    if store_kind not in STORE_KINDS:
        raise MacosStoreAccessError("Unknown store kind")
    return app_id, store_kind


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "approved_bindings", "access_declarations",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MacosStoreAccessError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise MacosStoreAccessError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    approved = [
        _binding(item, label="approved binding")
        for item in core.bounded_list(model["approved_bindings"], 64, "approved bindings")
    ]
    if len(approved) != len(set(approved)):
        raise MacosStoreAccessError("Approved bindings must be unique")
    declarations = core.bounded_list(model["access_declarations"], 64, "declarations")
    if not declarations:
        raise MacosStoreAccessError("At least one declaration is required")
    rows = []
    seen = set()
    for item in declarations:
        row = core.exact(item, {
            "access_id", "app_id", "store_kind", "access_declared",
        }, "access declaration")
        access_id = core.identifier(row["access_id"], "access ID")
        if access_id in seen:
            raise MacosStoreAccessError("Duplicate access ID")
        seen.add(access_id)
        binding = _binding({
            "app_id": row["app_id"], "store_kind": row["store_kind"],
        }, label="access binding")
        declared = core.boolean(row["access_declared"], "access declaration")
        flags = (
            ["store_access_outside_supplied_binding"]
            if declared and binding not in approved else []
        )
        rows.append({
            "access_id": access_id,
            "app_id": binding[0],
            "store_kind": binding[1],
            "access_declared": declared,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["access_id"])
    deviations = [row["access_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_store_access_inventory_incomplete"]
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
        "access_projections": rows,
        "declared_policy_deviation_access_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_store_access_projection",
        "source_authenticated": False,
        "host_connected": False,
        "store_connected": False,
        "secret_read": False,
        "cloud_content_read": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "App IDs, store kinds, bindings, access, and completeness are assertions.",
            "No Keychain item, iCloud content, credential, or secret is read.",
            "A binding mismatch is a review signal, not proof of unauthorized access.",
            "No host, store service, provider, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MSA-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class MacosStoreAccessReport:
    """Unsigned store-access projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MacosStoreAccessError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MacosStoreAccessReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_store_access(model: Any) -> MacosStoreAccessReport:
    return MacosStoreAccessReport._owned(_derive(model))


def verify_supplied_store_access(
    report: Any, *, model: Any
) -> MacosStoreAccessReport:
    if type(report) is not MacosStoreAccessReport:
        raise MacosStoreAccessError("Exact store access wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MacosStoreAccessError("Report differs from separate original model")
    return MacosStoreAccessReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-store-access",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "approved_bindings": [{"app_id": "app-a", "store_kind": "keychain"}],
        "access_declarations": [{
            "access_id": "access-a", "app_id": "app-b", "store_kind": "keychain",
            "access_declared": True,
        }],
    }
