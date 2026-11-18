"""Project supplied S3 public-read grants through current access controls."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "s3_supplied_public_grant_controls"
PROFILE_ID = "AOE-GC-D14-S11"
CAPABILITY_ID = "army.gc.d14.s11"
VECTOR_ID = "AV-GC-D14-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S11"
WAVE_ID = "IW2-014"
COMMANDER_ID = "AOE-GC-D14-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:5b91843023f9c507e723c2fdf56a3d2fc775ea13641027d3ef9cac801178307a"
DOMAIN = "sunderkey.offline-s3-public-grant-controls.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
SETTINGS = (
    "block_public_acls",
    "ignore_public_acls",
    "block_public_policy",
    "restrict_public_buckets",
)
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


class S3PublicGrantControlsError(ValueError):
    """A supplied S3 control model or replay is invalid."""


def _optional_boolean(value: Any, label: str) -> bool | None:
    if value is not None and type(value) is not bool:
        raise S3PublicGrantControlsError(f"{label} must be Boolean or unknown")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version",
            "source_id",
            "bucket_id",
            "context_complete",
            "bucket_owner_enforced",
            "public_read_acl",
            "public_read_policy",
            "organization_controls",
            "account_controls",
            "bucket_controls",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise S3PublicGrantControlsError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.identifier(model["bucket_id"], "bucket ID")
    core.boolean(model["context_complete"], "context completeness")
    for key in ("bucket_owner_enforced", "public_read_acl", "public_read_policy"):
        _optional_boolean(model[key], key)
    for layer in ("organization_controls", "account_controls", "bucket_controls"):
        controls = core.exact(model[layer], set(SETTINGS), layer)
        for setting in SETTINGS:
            _optional_boolean(controls[setting], f"{layer}.{setting}")
    return model, core.canonical(model)


def _effective(model: dict, setting: str) -> bool | None:
    values = [
        model[layer][setting]
        for layer in ("organization_controls", "account_controls", "bucket_controls")
    ]
    if True in values:
        return True
    if None in values:
        return None
    return False


def _acl_disposition(model: dict, ignored: bool | None) -> str:
    if not model["context_complete"] or model["public_read_acl"] is None:
        return "unknown"
    if model["public_read_acl"] is False:
        return "no_declared_public_read_acl"
    if model["bucket_owner_enforced"] is True:
        return "acl_disabled_by_object_ownership"
    if ignored is True:
        return "public_acl_ignored"
    if model["bucket_owner_enforced"] is None or ignored is None:
        return "unknown"
    return "candidate_declared_existing_public_acl_grant"


def _policy_disposition(model: dict, restricted: bool | None) -> str:
    if not model["context_complete"] or model["public_read_policy"] is None:
        return "unknown"
    if model["public_read_policy"] is False:
        return "no_declared_public_read_policy"
    if restricted is True:
        return "public_policy_restricted"
    if restricted is None:
        return "unknown"
    return "candidate_declared_existing_public_policy_grant"


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    effective = {setting: _effective(model, setting) for setting in SETTINGS}
    paths = [
        {
            "grant_path": "public_read_acl",
            "disposition": _acl_disposition(model, effective["ignore_public_acls"]),
        },
        {
            "grant_path": "public_read_policy",
            "disposition": _policy_disposition(model, effective["restrict_public_buckets"]),
        },
    ]
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "bucket_id": model["bucket_id"],
        "effective_controls": effective,
        "grant_path_projections": paths,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in paths),
        "unknown_count": sum(row["disposition"] == "unknown" for row in paths),
        "source_authenticated": False,
        "bucket_or_object_read": False,
        "policy_document_parsed": False,
        "public_reachability_claimed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Grant classification, ownership and controls are caller-supplied snapshots.",
            "BlockPublicAcls and BlockPublicPolicy reject writes, not existing grants.",
            "IgnorePublicAcls and RestrictPublicBuckets can suppress existing public grants.",
            "KMS, object state, conditions, denies, access points and reachability are omitted.",
            "A candidate is a declared grant path, not verified public object access.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SPG-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class S3PublicGrantControlsReport:
    """Unsigned supplied-control projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise S3PublicGrantControlsError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> S3PublicGrantControlsReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_s3_public_grants(model: Any) -> S3PublicGrantControlsReport:
    return S3PublicGrantControlsReport._owned(_derive(model))


def verify_supplied_s3_public_grants(report: Any, *, model: Any) -> S3PublicGrantControlsReport:
    if type(report) is not S3PublicGrantControlsReport:
        raise S3PublicGrantControlsError("Exact S3 grant wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise S3PublicGrantControlsError("Report differs from separate original model")
    return S3PublicGrantControlsReport._owned(expected)


def verify_supplied_s3_public_grants_bytes(
    report_bytes: bytes, *, model: Any
) -> S3PublicGrantControlsReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise S3PublicGrantControlsError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise S3PublicGrantControlsError("Exported report differs from original replay")
    return S3PublicGrantControlsReport._owned(expected)


def component_fixture() -> dict:
    settings = {setting: False for setting in SETTINGS}
    return {
        "schema_version": 1,
        "source_id": "synthetic-s3-controls",
        "bucket_id": "synthetic-bucket",
        "context_complete": True,
        "bucket_owner_enforced": False,
        "public_read_acl": True,
        "public_read_policy": True,
        "organization_controls": dict(settings),
        "account_controls": dict(settings),
        "bucket_controls": {
            **settings,
            "block_public_acls": True,
            "block_public_policy": True,
        },
    }
