"""Compare supplied AD CS template rights with an explicit local policy."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "adcs_supplied_template_rights_projection"
PROFILE_ID = "AOE-GC-D11-S04"
CAPABILITY_ID = "army.gc.d11.s04"
VECTOR_ID = "AV-GC-D11-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S04"
WAVE_ID = "IW2-004"
COMMANDER_ID = "AOE-GC-D11-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:d92911a622b09b37022c96291a557fdbadb923ce3ea73d5d6ac19bff6eacc726"
DOMAIN = "sunderkey.offline-adcs-template-rights.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
RIGHT_LABELS = {"read", "enroll", "autoenroll"}
PRINCIPAL_REF = re.compile(r"principal:sha256:[0-9a-f]{64}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class AdcsTemplateRightsError(ValueError):
    """A supplied template-rights model or original-model replay is invalid."""


def _principal(value: Any) -> str:
    if type(value) is not str or PRINCIPAL_REF.fullmatch(value) is None:
        raise AdcsTemplateRightsError("Principal must be an opaque digest reference")
    return value


def _principal_list(value: Any, label: str) -> list[str]:
    refs = core.bounded_list(value, 64, label)
    for ref in refs:
        _principal(ref)
    if len(refs) != len(set(refs)):
        raise AdcsTemplateRightsError(f"{label} contains a duplicate")
    return refs


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "policy", "templates"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AdcsTemplateRightsError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    policy = core.exact(
        model["policy"],
        {"require_read_with_enrollment", "require_enroll_with_autoenroll"},
        "policy",
    )
    core.boolean(policy["require_read_with_enrollment"], "read policy")
    core.boolean(policy["require_enroll_with_autoenroll"], "autoenroll policy")
    templates = core.bounded_list(model["templates"], 32, "templates")
    if not templates:
        raise AdcsTemplateRightsError("At least one template is required")
    template_ids: set[str] = set()
    for template in templates:
        row = core.exact(
            template,
            {"template_id", "allowed_enrollment_principal_refs", "principal_rights"},
            "template",
        )
        template_id = core.identifier(row["template_id"], "template ID")
        if template_id in template_ids:
            raise AdcsTemplateRightsError("Duplicate template ID")
        template_ids.add(template_id)
        _principal_list(row["allowed_enrollment_principal_refs"], "allowed principals")
        declarations = core.bounded_list(row["principal_rights"], 64, "principal rights")
        seen_principals: set[str] = set()
        for declaration in declarations:
            grant = core.exact(
                declaration, {"principal_ref", "allow_right_labels"}, "principal rights"
            )
            principal = _principal(grant["principal_ref"])
            if principal in seen_principals:
                raise AdcsTemplateRightsError("Duplicate principal rights declaration")
            seen_principals.add(principal)
            rights = core.bounded_list(grant["allow_right_labels"], 3, "allow rights")
            for right in rights:
                core.choice(right, RIGHT_LABELS, "allow right")
            if len(rights) != len(set(rights)):
                raise AdcsTemplateRightsError("Duplicate allow right")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    complete = model["inventory_complete"]
    policy = model["policy"]
    rows = []
    mismatches = []
    for template in model["templates"]:
        allowed = set(template["allowed_enrollment_principal_refs"])
        for declaration in template["principal_rights"]:
            rights = set(declaration["allow_right_labels"])
            enrollment_declared = bool(rights & {"enroll", "autoenroll"})
            issues = []
            if enrollment_declared and declaration["principal_ref"] not in allowed:
                issues.append("enrollment_principal_outside_supplied_allowlist")
            if (
                enrollment_declared
                and policy["require_read_with_enrollment"]
                and "read" not in rights
            ):
                issues.append("required_read_not_declared")
            if (
                "autoenroll" in rights
                and policy["require_enroll_with_autoenroll"]
                and "enroll" not in rights
            ):
                issues.append("required_enroll_not_declared")
            row = {
                "template_id": template["template_id"],
                "principal_ref": declaration["principal_ref"],
                "allow_right_labels": sorted(rights),
                "enrollment_right_declared": enrollment_declared,
                "policy_issues": issues if complete else None,
                "row_disposition": "evaluated" if complete else "unknown_incomplete_inventory",
            }
            rows.append(row)
            if complete and issues:
                mismatches.append({
                    "template_id": template["template_id"],
                    "principal_ref": declaration["principal_ref"],
                    "policy_issues": issues,
                })
    disposition = (
        "unknown" if not complete else
        "candidate_supplied_template_policy_mismatch" if mismatches else
        "supplied_template_rights_match"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "template_count": len(model["templates"]),
        "declaration_count": len(rows),
        "rows": rows,
        "mismatches": mismatches,
        "disposition": disposition,
        "candidate_count": len(mismatches) if complete else 0,
        "unknown_count": int(not complete),
        "directory_source_authenticated": False,
        "template_rights_authenticated": False,
        "effective_enrollment_access_verified": False,
        "certificate_issued": False,
        "esc_classification_claimed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Template rights, principal references, allowlists and completeness are "
            "caller-supplied.",
            "Read and Enroll combinations are evaluated only against the supplied local policy.",
            "Deny rights, group expansion, inherited rights and effective access are "
            "not evaluated.",
            "CA publication, issuance rules, certificate issuance and exploitability "
            "are not verified.",
            "No directory, certification authority, credential, service, network or "
            "target is contacted.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="ATR-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class AdcsTemplateRightsReport:
    """Unsigned template-rights projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise AdcsTemplateRightsError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> AdcsTemplateRightsReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_adcs_template_rights(model: Any) -> AdcsTemplateRightsReport:
    """Project declared template rights against only the supplied local policy."""
    return AdcsTemplateRightsReport._owned(_derive(model))


def verify_supplied_adcs_template_rights(
    report: Any, *, model: Any
) -> AdcsTemplateRightsReport:
    if type(report) is not AdcsTemplateRightsReport:
        raise AdcsTemplateRightsError("Exact AD CS template-rights wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise AdcsTemplateRightsError("Report differs from separate original model")
    return AdcsTemplateRightsReport._owned(expected)


def verify_supplied_adcs_template_rights_bytes(
    report_bytes: bytes, *, model: Any
) -> AdcsTemplateRightsReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise AdcsTemplateRightsError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise AdcsTemplateRightsError("Exported report differs from original replay")
    return AdcsTemplateRightsReport._owned(expected)


def component_fixture() -> dict:
    authorized = "principal:sha256:" + "a" * 64
    other = "principal:sha256:" + "b" * 64
    return {
        "schema_version": 1,
        "source_id": "synthetic-adcs-template-rights",
        "inventory_complete": True,
        "policy": {
            "require_read_with_enrollment": True,
            "require_enroll_with_autoenroll": True,
        },
        "templates": [{
            "template_id": "synthetic-user-template",
            "allowed_enrollment_principal_refs": [authorized],
            "principal_rights": [
                {"principal_ref": authorized, "allow_right_labels": ["read", "enroll"]},
                {"principal_ref": other, "allow_right_labels": ["autoenroll"]},
            ],
        }],
    }
