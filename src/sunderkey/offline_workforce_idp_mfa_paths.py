"""Compare supplied privileged application paths with declared MFA policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "idp_supplied_privileged_mfa_path_policy"
PROFILE_ID = "AOE-GC-D14-S20"
CAPABILITY_ID = "army.gc.d14.s20"
VECTOR_ID = "AV-GC-D14-S20-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S20"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GC-D14-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:667766c57dd304d711388cd40311a8a72f7e519212787d80cfc196bb705fdd62"
DOMAIN = "sunderkey.offline-workforce-idp-mfa-paths.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
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


class WorkforceIdpMfaPathError(ValueError):
    """A supplied IdP path model or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "applications"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WorkforceIdpMfaPathError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    applications = core.bounded_list(model["applications"], 32, "applications")
    if not applications:
        raise WorkforceIdpMfaPathError("At least one application is required")
    seen_applications: set[str] = set()
    for item in applications:
        app = core.exact(
            item,
            {
                "application_id",
                "privileged",
                "mfa_required",
                "policy_complete",
                "sign_in_paths",
            },
            "application",
        )
        app_id = core.identifier(app["application_id"], "application ID")
        if app_id in seen_applications:
            raise WorkforceIdpMfaPathError("Duplicate application ID")
        seen_applications.add(app_id)
        for key in ("privileged", "mfa_required", "policy_complete"):
            core.boolean(app[key], key)
        paths = core.bounded_list(app["sign_in_paths"], 16, "sign-in paths")
        seen_paths: set[str] = set()
        for item_path in paths:
            path = core.exact(
                item_path,
                {"path_id", "enabled", "declared_mfa_enforced"},
                "sign-in path",
            )
            path_id = core.identifier(path["path_id"], "path ID")
            if path_id in seen_paths:
                raise WorkforceIdpMfaPathError("Duplicate path ID")
            seen_paths.add(path_id)
            core.boolean(path["enabled"], "path enabled")
            core.boolean(path["declared_mfa_enforced"], "declared MFA enforcement")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for app in model["applications"]:
        unprotected = sorted(
            path["path_id"]
            for path in app["sign_in_paths"]
            if path["enabled"] and not path["declared_mfa_enforced"]
        )
        disposition = (
            "unknown"
            if not app["policy_complete"]
            else "candidate_declared_privileged_mfa_path_gap"
            if app["privileged"] and app["mfa_required"] and unprotected
            else "no_declared_privileged_mfa_path_gap"
        )
        projections.append(
            {
                "application_id": app["application_id"],
                "enabled_without_declared_mfa_path_ids": unprotected,
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
        "application_count": len(model["applications"]),
        "application_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "idp_queried": False,
        "effective_policy_verified": False,
        "authentication_bypass_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Application labels, MFA requirements and path states are caller-supplied.",
            "Conditional access, inherited rules and real sign-in outcomes are not evaluated.",
            "A declared path mismatch does not prove a usable authentication bypass.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="IDM-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class WorkforceIdpMfaPathReport:
    """Unsigned IdP policy projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise WorkforceIdpMfaPathError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> WorkforceIdpMfaPathReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_workforce_idp_mfa_paths(model: Any) -> WorkforceIdpMfaPathReport:
    return WorkforceIdpMfaPathReport._owned(_derive(model))


def verify_supplied_workforce_idp_mfa_paths(
    report: Any, *, model: Any
) -> WorkforceIdpMfaPathReport:
    if type(report) is not WorkforceIdpMfaPathReport:
        raise WorkforceIdpMfaPathError("Exact IdP MFA-path wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise WorkforceIdpMfaPathError("Report differs from separate original model")
    return WorkforceIdpMfaPathReport._owned(expected)


def verify_supplied_workforce_idp_mfa_paths_bytes(
    report_bytes: bytes, *, model: Any
) -> WorkforceIdpMfaPathReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise WorkforceIdpMfaPathError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise WorkforceIdpMfaPathError("Exported report differs from original replay")
    return WorkforceIdpMfaPathReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-idp-policy",
        "applications": [
            {
                "application_id": "admin-app",
                "privileged": True,
                "mfa_required": True,
                "policy_complete": True,
                "sign_in_paths": [
                    {"path_id": "standard", "enabled": True, "declared_mfa_enforced": True},
                    {"path_id": "legacy", "enabled": True, "declared_mfa_enforced": False},
                ],
            }
        ],
    }
