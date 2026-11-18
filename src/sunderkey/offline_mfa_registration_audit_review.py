"""Review one supplied synthetic Entra MFA audit item without Graph I/O."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "social_supplied_mfa_registration_audit_review"
PROFILE_ID = "AOE-GA-D02-S05"
CAPABILITY_ID = "army.ga.d02.s05"
VECTOR_ID = "AV-GA-D02-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D02-S05"
WAVE_ID = "IW2-006"
COMMANDER_ID = "AOE-GA-D02-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:f58cf1d6f2fd719012e97917389aac8e9bc3ac16129b8be5bc2201d1ee782feb"
DOMAIN = "sunderkey.offline-mfa-registration-audit-review.v1"
MAX_MODEL_BYTES = 8_192
MAX_REPORT_BYTES = 32_768
GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
UTC_SECOND = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
ACTIVITIES = {
    "Admin registered security info",
    "User registered security info",
    "User started security info registration",
    "User canceled security info registration",
}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class MfaRegistrationAuditReviewError(ValueError):
    """A synthetic MFA audit declaration or replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise MfaRegistrationAuditReviewError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise MfaRegistrationAuditReviewError("Model exceeds byte bound")
    return result


def _guid(value: Any, label: str) -> str:
    if type(value) is not str or GUID.fullmatch(value) is None:
        raise MfaRegistrationAuditReviewError(f"Synthetic {label} GUID required")
    return value


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "directory_audit",
         "expected_actor_id", "expected_target_id"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MfaRegistrationAuditReviewError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise MfaRegistrationAuditReviewError("Only synthetic fixtures are accepted")
    expected_actor = _guid(model["expected_actor_id"], "actor")
    expected_target = _guid(model["expected_target_id"], "target")
    audit = core.exact(
        model["directory_audit"],
        {"activityDateTime", "activityDisplayName", "category",
         "initiatedBy", "loggedByService", "result", "targetResources"},
        "directory audit",
    )
    when = audit["activityDateTime"]
    if type(when) is not str or UTC_SECOND.fullmatch(when) is None:
        raise MfaRegistrationAuditReviewError("UTC audit time required")
    try:
        datetime.fromisoformat(when.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        raise MfaRegistrationAuditReviewError("Invalid audit time") from exc
    activity = audit["activityDisplayName"]
    result = audit["result"]
    if (type(activity) is not str or activity not in ACTIVITIES
            or type(audit["category"]) is not str
            or audit["category"] != "UserManagement"
            or type(audit["loggedByService"]) is not str
            or audit["loggedByService"] != "Authentication Methods"
            or type(result) is not str
            or result not in {"success", "failure", "timeout"}):
        raise MfaRegistrationAuditReviewError("Closed MFA activity fields required")
    actor = core.exact(audit["initiatedBy"], {"user"}, "initiator")
    actor_id = _guid(
        core.exact(actor["user"], {"id"}, "initiator user")["id"], "actor"
    )
    resources = audit["targetResources"]
    if type(resources) is not list or len(resources) != 1:
        raise MfaRegistrationAuditReviewError("One target User required")
    target = core.exact(resources[0], {"id", "type"}, "target resource")
    if target["type"] != "User":
        raise MfaRegistrationAuditReviewError("Target must be a User")
    target_id = _guid(target["id"], "target")
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
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "synthetic_fixture_asserted": True,
        "audit_item_sha256": _hash(core.canonical(audit)),
        "actor_id_sha256": _hash(actor_id),
        "target_id_sha256": _hash(target_id),
        "actor_matches_supplied_expectation": actor_id == expected_actor,
        "target_matches_supplied_expectation": target_id == expected_target,
        "activity": activity,
        "declared_result": result,
        "declared_time_utc": when,
        "registration_verified": False,
        "help_desk_contact_verified": False,
        "mfa_method_control_verified": False,
        "candidate_count": 0,
        "uncertainty": [
            "audit_origin_and_completeness_unverified",
            "initiator_and_target_identity_unverified",
            "actual_method_state_and_human_contact_unobserved",
        ],
        "unknown_count": 3,
        "disposition": "unknown",
        "source_authenticated": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only one synthetic Microsoft Graph directoryAudit subset is read.",
            "A declared success is not independent proof of registered MFA state.",
            "Actor, target, tenant, and human contact remain unauthenticated.",
            "No Graph request, help-desk contact, or MFA change occurs.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MAR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class MfaRegistrationAuditReviewReport:
    """Unsigned audit projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MfaRegistrationAuditReviewError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MfaRegistrationAuditReviewReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_mfa_registration_audit(
    model: Any,
) -> MfaRegistrationAuditReviewReport:
    return MfaRegistrationAuditReviewReport._owned(_derive(model))


def verify_supplied_mfa_registration_audit(
    report: Any, *, model: Any
) -> MfaRegistrationAuditReviewReport:
    if type(report) is not MfaRegistrationAuditReviewReport:
        raise MfaRegistrationAuditReviewError("Exact MFA audit wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MfaRegistrationAuditReviewError("Report differs from separate original model")
    return MfaRegistrationAuditReviewReport._owned(expected)


def component_fixture() -> dict:
    actor = "11111111-1111-1111-1111-111111111111"
    target = "22222222-2222-2222-2222-222222222222"
    return {
        "schema_version": 1,
        "source_id": "synthetic-mfa-registration-audit",
        "synthetic_fixture": True,
        "directory_audit": {
            "activityDateTime": "2026-01-01T00:00:00Z",
            "activityDisplayName": "Admin registered security info",
            "category": "UserManagement",
            "initiatedBy": {"user": {"id": actor}},
            "loggedByService": "Authentication Methods",
            "result": "success",
            "targetResources": [{"id": target, "type": "User"}],
        },
        "expected_actor_id": actor,
        "expected_target_id": target,
    }
