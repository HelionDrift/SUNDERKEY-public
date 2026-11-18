"""Compare supplied collaboration grants with external-sharing policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "workspace_supplied_external_sharing_policy"
PROFILE_ID = "AOE-GC-D14-S19"
CAPABILITY_ID = "army.gc.d14.s19"
VECTOR_ID = "AV-GC-D14-S19-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S19"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GC-D14-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:c6c67fcb9e30bfe3a418639bdd55a28f252ab410f4435907402a5fe34c5c0aec"
DOMAIN = "sunderkey.offline-workspace-external-sharing.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
ROLES = {"viewer", "commenter", "editor", "owner"}
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


class WorkspaceExternalSharingError(ValueError):
    """A supplied collaboration grant model or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "internal_domain_id", "scopes"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WorkspaceExternalSharingError("Unsupported model version")
    for key in ("source_id", "internal_domain_id"):
        core.identifier(model[key], key)
    scopes = core.bounded_list(model["scopes"], 16, "scopes")
    if not scopes:
        raise WorkspaceExternalSharingError("At least one scope is required")
    seen_scopes: set[str] = set()
    for item in scopes:
        row = core.exact(
            item,
            {"scope_id", "external_sharing_allowed", "context_complete", "grants"},
            "scope",
        )
        scope_id = core.identifier(row["scope_id"], "scope ID")
        if scope_id in seen_scopes:
            raise WorkspaceExternalSharingError("Duplicate scope ID")
        seen_scopes.add(scope_id)
        core.boolean(row["external_sharing_allowed"], "external-sharing policy")
        core.boolean(row["context_complete"], "context completeness")
        grants = core.bounded_list(row["grants"], 32, "grants")
        seen_grants: set[str] = set()
        for item_grant in grants:
            grant = core.exact(
                item_grant,
                {"grant_id", "document_id", "recipient_domain_id", "role", "active"},
                "grant",
            )
            grant_id = core.identifier(grant["grant_id"], "grant ID")
            if grant_id in seen_grants:
                raise WorkspaceExternalSharingError("Duplicate grant ID")
            seen_grants.add(grant_id)
            for key in ("document_id", "recipient_domain_id"):
                core.identifier(grant[key], key)
            core.choice(grant["role"], ROLES, "grant role")
            core.boolean(grant["active"], "grant activity")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for row in model["scopes"]:
        external = sorted(
            grant["grant_id"]
            for grant in row["grants"]
            if grant["active"] and grant["recipient_domain_id"] != model["internal_domain_id"]
        )
        disposition = (
            "unknown"
            if not row["context_complete"]
            else "candidate_declared_external_share_policy_mismatch"
            if not row["external_sharing_allowed"] and external
            else "no_declared_external_share_policy_mismatch"
        )
        projections.append(
            {
                "scope_id": row["scope_id"],
                "active_external_grant_ids": external,
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
        "scope_count": len(model["scopes"]),
        "scope_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "workspace_queried": False,
        "grant_effectiveness_verified": False,
        "document_exposure_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Tenant domain, policies and document grants are caller-supplied.",
            "Inherited policy, link sharing, groups and provider enforcement are not evaluated.",
            "A policy mismatch does not prove document access or data disclosure.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="WES-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class WorkspaceExternalSharingReport:
    """Unsigned sharing projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise WorkspaceExternalSharingError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> WorkspaceExternalSharingReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_workspace_sharing(model: Any) -> WorkspaceExternalSharingReport:
    return WorkspaceExternalSharingReport._owned(_derive(model))


def verify_supplied_workspace_sharing(report: Any, *, model: Any) -> WorkspaceExternalSharingReport:
    if type(report) is not WorkspaceExternalSharingReport:
        raise WorkspaceExternalSharingError("Exact workspace-sharing wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise WorkspaceExternalSharingError("Report differs from separate original model")
    return WorkspaceExternalSharingReport._owned(expected)


def verify_supplied_workspace_sharing_bytes(
    report_bytes: bytes, *, model: Any
) -> WorkspaceExternalSharingReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise WorkspaceExternalSharingError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise WorkspaceExternalSharingError("Exported report differs from original replay")
    return WorkspaceExternalSharingReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-workspace-grants",
        "internal_domain_id": "internal.example",
        "scopes": [
            {
                "scope_id": "scope-one",
                "external_sharing_allowed": False,
                "context_complete": True,
                "grants": [
                    {
                        "grant_id": "grant-one",
                        "document_id": "document-one",
                        "recipient_domain_id": "external.example",
                        "role": "viewer",
                        "active": True,
                    },
                    {
                        "grant_id": "grant-two",
                        "document_id": "document-two",
                        "recipient_domain_id": "internal.example",
                        "role": "editor",
                        "active": True,
                    },
                ],
            }
        ],
    }
