"""Compare synthetic legacy-platform grant declarations with supplied policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

_SPECS = {
    "zos": (
        "AOE-GC-D16-S01", "IW2-013",
        "sha256:1147f7ed1a8570604b0d28a3c9aa185b360123d7f1111bf59a67f4f2ba331784",
        "legacy_supplied_zos_grant_policy_projection",
    ),
    "ibmi": (
        "AOE-GC-D16-S02", "IW2-014",
        "sha256:eca406ceae47d0ca9ab420376d72af427de6aef6864cde1ba32c70068cd33c83",
        "legacy_supplied_ibmi_grant_policy_projection",
    ),
    "unix_enterprise": (
        "AOE-GC-D16-S03", "IW2-015",
        "sha256:4024ea44c78a65be7894977c11f670a9bd20cf817fb97ce7bf0b58f616af46e1",
        "legacy_supplied_unix_grant_policy_projection",
    ),
    "sap": (
        "AOE-GC-D16-S04", "IW2-016",
        "sha256:c4922bc5a48a3d84665dcf4772fc47d0a37581f565bedcc330bc492edb7ea364",
        "legacy_supplied_sap_grant_policy_projection",
    ),
    "oracle_enterprise": (
        "AOE-GC-D16-S05", "IW2-017",
        "sha256:9c854569c1729b89be4a57e8db9ae6668e7e82917ac343e13c4b90bf076f9b49",
        "legacy_supplied_oracle_grant_policy_projection",
    ),
}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class LegacyGrantPolicyError(ValueError):
    """A supplied legacy grant model or original-model replay is invalid."""


def _grants(value: Any, *, label: str) -> set[tuple[str, str, str]]:
    grants = set()
    for item in core.bounded_list(value, 64, label):
        row = core.exact(item, {
            "principal_ref", "resource_ref", "privilege_ref",
        }, label)
        triple = (
            core.identifier(row["principal_ref"], "opaque principal reference"),
            core.identifier(row["resource_ref"], "opaque resource reference"),
            core.identifier(row["privilege_ref"], "opaque privilege reference"),
        )
        if triple in grants:
            raise LegacyGrantPolicyError(f"Duplicate {label} grant")
        grants.add(triple)
    return grants


def _derive(value: Any, *, platform_kind: str) -> dict:
    if platform_kind not in _SPECS:
        raise LegacyGrantPolicyError("Unknown closed platform kind")
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "platform_kind", "allowed_grants", "declared_grants",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise LegacyGrantPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise LegacyGrantPolicyError("Only synthetic fixtures are accepted")
    if model["platform_kind"] != platform_kind:
        raise LegacyGrantPolicyError("Model platform kind differs from specialist")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    allowed = _grants(model["allowed_grants"], label="allowed grants")
    declared = _grants(model["declared_grants"], label="declared grants")
    if not declared:
        raise LegacyGrantPolicyError("At least one declared grant is required")
    deviations = sorted(declared - allowed)
    profile_id, wave_id, blueprint_sha256, component_id = _SPECS[platform_kind]
    segment = profile_id.rsplit("-", 1)[-1].lower()
    unknown = [] if complete else ["supplied_grant_inventory_incomplete"]
    body = {
        "schema_version": 1,
        "component_id": component_id,
        "profile_id": profile_id,
        "capability_id": f"army.gc.d16.{segment}",
        "vector_id": f"AV-GC-D16-{profile_id.rsplit('-', 1)[-1]}-01",
        "work_package_id": f"IWP2-{profile_id}",
        "wave_id": wave_id,
        "commander_id": "AOE-GC-D16-CMD",
        "group_owner_id": "AOE-HQ-05",
        "independent_validator_id": "AOE-HQ-19",
        "blueprint_sha256": blueprint_sha256,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "inventory_complete_asserted": complete,
        "platform_kind": platform_kind,
        "declared_grant_count": len(declared),
        "outside_supplied_policy_grants": [
            {
                "principal_ref": principal,
                "resource_ref": resource,
                "privilege_ref": privilege,
            }
            for principal, resource, privilege in deviations
        ],
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_legacy_grant_projection",
        "source_authenticated": False,
        "platform_connected": False,
        "credential_used": False,
        "grant_changed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Grant policy, declarations, and completeness are synthetic assertions.",
            "Opaque references do not establish platform-specific privilege semantics.",
            "The model does not establish effective access or an exploitable path.",
            "No platform, credential, network, account, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(
        body, domain=f"sunderkey.offline-legacy-grants.{platform_kind}.v1", prefix="LGP-"
    )
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class LegacyGrantPolicyReport:
    """Unsigned grant projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise LegacyGrantPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> LegacyGrantPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_legacy_grants(
    model: Any, *, platform_kind: str
) -> LegacyGrantPolicyReport:
    return LegacyGrantPolicyReport._owned(_derive(model, platform_kind=platform_kind))


def verify_supplied_legacy_grants(
    report: Any, *, model: Any, platform_kind: str
) -> LegacyGrantPolicyReport:
    if type(report) is not LegacyGrantPolicyReport:
        raise LegacyGrantPolicyError("Exact legacy grant wrapper required")
    expected = _derive(model, platform_kind=platform_kind)
    if report.to_json() != core.canonical(expected):
        raise LegacyGrantPolicyError("Report differs from separate original model")
    return LegacyGrantPolicyReport._owned(expected)


def component_fixture(platform_kind: str) -> dict:
    if platform_kind not in _SPECS:
        raise LegacyGrantPolicyError("Unknown closed platform kind")
    return {
        "schema_version": 1,
        "source_id": f"synthetic-{platform_kind}-grants",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "platform_kind": platform_kind,
        "allowed_grants": [{
            "principal_ref": "principal-a", "resource_ref": "resource-a",
            "privilege_ref": "privilege-a",
        }],
        "declared_grants": [{
            "principal_ref": "principal-b", "resource_ref": "resource-a",
            "privilege_ref": "privilege-a",
        }],
    }


def analyze_supplied_zos_grants(model: Any) -> LegacyGrantPolicyReport:
    return analyze_supplied_legacy_grants(model, platform_kind="zos")


def analyze_supplied_ibmi_grants(model: Any) -> LegacyGrantPolicyReport:
    return analyze_supplied_legacy_grants(model, platform_kind="ibmi")


def analyze_supplied_unix_enterprise_grants(model: Any) -> LegacyGrantPolicyReport:
    return analyze_supplied_legacy_grants(model, platform_kind="unix_enterprise")


def analyze_supplied_sap_grants(model: Any) -> LegacyGrantPolicyReport:
    return analyze_supplied_legacy_grants(model, platform_kind="sap")


def analyze_supplied_oracle_enterprise_grants(model: Any) -> LegacyGrantPolicyReport:
    return analyze_supplied_legacy_grants(model, platform_kind="oracle_enterprise")
