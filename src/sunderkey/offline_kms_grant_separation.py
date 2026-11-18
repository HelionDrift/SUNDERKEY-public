"""Compare supplied KMS grants with an explicit separation requirement."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "cloud_supplied_kms_grant_separation"
PROFILE_ID = "AOE-GC-D14-S13"
CAPABILITY_ID = "army.gc.d14.s13"
VECTOR_ID = "AV-GC-D14-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S13"
WAVE_ID = "IW2-016"
COMMANDER_ID = "AOE-GC-D14-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:dbf2c8465568e400387fc500cb8a19824073a7a96f43d921c70b6b6d02f2d1a1"
DOMAIN = "sunderkey.offline-kms-grant-separation.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
ACTIONS = {"decrypt", "encrypt", "describe", "manage_policy"}
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


class KmsGrantSeparationError(ValueError):
    """A supplied KMS grant model or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "keys"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise KmsGrantSeparationError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    keys = core.bounded_list(model["keys"], 16, "keys")
    if not keys:
        raise KmsGrantSeparationError("At least one key is required")
    seen_keys: set[str] = set()
    for item in keys:
        row = core.exact(
            item, {"key_id", "separation_required", "context_complete", "grants"}, "key"
        )
        key_id = core.identifier(row["key_id"], "key ID")
        if key_id in seen_keys:
            raise KmsGrantSeparationError("Duplicate key ID")
        seen_keys.add(key_id)
        core.boolean(row["separation_required"], "separation requirement")
        core.boolean(row["context_complete"], "context completeness")
        grants = core.bounded_list(row["grants"], 32, "grants")
        seen_grants: set[str] = set()
        for item_grant in grants:
            grant = core.exact(
                item_grant, {"grant_id", "principal_id", "actions", "active"}, "grant"
            )
            grant_id = core.identifier(grant["grant_id"], "grant ID")
            if grant_id in seen_grants:
                raise KmsGrantSeparationError("Duplicate grant ID")
            seen_grants.add(grant_id)
            core.identifier(grant["principal_id"], "principal ID")
            core.boolean(grant["active"], "grant activity")
            actions = core.bounded_list(grant["actions"], 4, "grant actions")
            if not actions:
                raise KmsGrantSeparationError("Grant must declare an action")
            for action in actions:
                core.choice(action, ACTIONS, "grant action")
            if len(actions) != len(set(actions)):
                raise KmsGrantSeparationError("Duplicate grant action")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for row in model["keys"]:
        effective: dict[str, set[str]] = defaultdict(set)
        for grant in row["grants"]:
            if grant["active"]:
                effective[grant["principal_id"]].update(grant["actions"])
        overlapping = sorted(
            principal
            for principal, actions in effective.items()
            if {"decrypt", "manage_policy"}.issubset(actions)
        )
        disposition = (
            "unknown"
            if not row["context_complete"]
            else "candidate_declared_kms_duties_overlap"
            if row["separation_required"] and overlapping
            else "no_declared_kms_duties_overlap"
        )
        projections.append(
            {
                "key_id": row["key_id"],
                "active_principal_count": len(effective),
                "overlapping_principal_ids": overlapping,
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "key_count": len(model["keys"]),
        "key_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "kms_queried": False,
        "grant_effectiveness_verified": False,
        "key_material_access_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Key policy, grant activity and principal identities are caller-supplied.",
            "Effective provider policy, deny rules and grant constraints are not evaluated.",
            "An overlap is a supplied separation-policy signal, not proof of key use.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="KGS-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class KmsGrantSeparationReport:
    """Unsigned grant projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise KmsGrantSeparationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> KmsGrantSeparationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_kms_grants(model: Any) -> KmsGrantSeparationReport:
    return KmsGrantSeparationReport._owned(_derive(model))


def verify_supplied_kms_grants(report: Any, *, model: Any) -> KmsGrantSeparationReport:
    if type(report) is not KmsGrantSeparationReport:
        raise KmsGrantSeparationError("Exact KMS-grant wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise KmsGrantSeparationError("Report differs from separate original model")
    return KmsGrantSeparationReport._owned(expected)


def verify_supplied_kms_grants_bytes(
    report_bytes: bytes, *, model: Any
) -> KmsGrantSeparationReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise KmsGrantSeparationError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise KmsGrantSeparationError("Exported report differs from original replay")
    return KmsGrantSeparationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-kms-grants",
        "keys": [
            {
                "key_id": "key-one",
                "separation_required": True,
                "context_complete": True,
                "grants": [
                    {
                        "grant_id": "grant-one",
                        "principal_id": "principal-a",
                        "actions": ["decrypt"],
                        "active": True,
                    },
                    {
                        "grant_id": "grant-two",
                        "principal_id": "principal-a",
                        "actions": ["manage_policy"],
                        "active": True,
                    },
                    {
                        "grant_id": "grant-three",
                        "principal_id": "principal-b",
                        "actions": ["encrypt"],
                        "active": True,
                    },
                ],
            }
        ],
    }
