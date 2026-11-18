"""Compare supplied direct app-role assignments with opaque claim labels."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_entra_role_claim_review"
PROFILE_ID = "AOE-GC-D11-S14"
CAPABILITY_ID = "enterprise.entra-id"
VECTOR_ID = "AV-GC-D11-S14-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S14"
WAVE_ID = "IW2-014"
COMMANDER_ID = "AOE-GC-D11-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:cfca619007f721836d8d1b81ee1c353704f4090876859596cc63be418c336924"
SEMANTICS_PROFILE = "supplied-entra-direct-role-claim-review-v1"
DOMAIN = "sunderkey.offline-entra-role-claim-review.v1"
MAX_ASSIGNMENTS = 256
MAX_OBSERVATIONS = 128
MAX_ROLES_PER_OBSERVATION = 16
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TENANT = re.compile(r"tenant:sha256:[0-9a-f]{64}\Z")
_SUBJECT = re.compile(r"subject:sha256:[0-9a-f]{64}\Z")
_RESOURCE = re.compile(r"resource:sha256:[0-9a-f]{64}\Z")
_ROLE = re.compile(r"role:sha256:[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"token:sha256:[0-9a-f]{64}\Z")
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "filesystem",
        "network",
        "publication",
        "qualification",
        "target",
        "token_validation",
    ),
    "none",
)


class EntraRoleClaimReviewError(ValueError):
    """The supplied role/claim model or report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise EntraRoleClaimReviewError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise EntraRoleClaimReviewError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise EntraRoleClaimReviewError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise EntraRoleClaimReviewError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise EntraRoleClaimReviewError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise EntraRoleClaimReviewError("Native JSON text keys are required")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        finally:
            active.remove(id(item))

    visit(value, 1)
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise EntraRoleClaimReviewError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise EntraRoleClaimReviewError(f"{label} fields are invalid")


def _ref(value: Any, pattern: re.Pattern, label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise EntraRoleClaimReviewError(f"{label} must be an opaque digest reference")
    return value


def _id(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise EntraRoleClaimReviewError(f"{label} identifier is invalid")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {"schema_version", "semantics_profile", "tenant_ref", "assignments", "observations"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise EntraRoleClaimReviewError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise EntraRoleClaimReviewError("Semantics profile is invalid")
    _ref(model["tenant_ref"], _TENANT, "Tenant")
    assignments = model["assignments"]
    if type(assignments) is not list or len(assignments) > MAX_ASSIGNMENTS:
        raise EntraRoleClaimReviewError("Assignment count is invalid")
    assignment_ids: set[str] = set()
    assignment_keys: set[tuple[str, str, str]] = set()
    for assignment in assignments:
        _fields(
            assignment,
            {"assignment_id", "subject_ref", "resource_ref", "role_ref", "active"},
            "assignment",
        )
        assignment_id = _id(assignment["assignment_id"], "Assignment")
        if assignment_id in assignment_ids:
            raise EntraRoleClaimReviewError("Duplicate assignment identifier")
        assignment_ids.add(assignment_id)
        key = (
            _ref(assignment["subject_ref"], _SUBJECT, "Subject"),
            _ref(assignment["resource_ref"], _RESOURCE, "Resource"),
            _ref(assignment["role_ref"], _ROLE, "Role"),
        )
        if key in assignment_keys:
            raise EntraRoleClaimReviewError("Duplicate assignment tuple")
        assignment_keys.add(key)
        if type(assignment["active"]) is not bool:
            raise EntraRoleClaimReviewError("Assignment activity must be an exact boolean")
    observations = model["observations"]
    if type(observations) is not list or not 1 <= len(observations) <= MAX_OBSERVATIONS:
        raise EntraRoleClaimReviewError("Observation count is invalid")
    tokens: set[str] = set()
    for observation in observations:
        _fields(
            observation,
            {"token_ref", "declared_tenant_ref", "subject_ref", "resource_ref", "role_refs"},
            "observation",
        )
        token = _ref(observation["token_ref"], _TOKEN, "Token")
        if token in tokens:
            raise EntraRoleClaimReviewError("Duplicate token reference")
        tokens.add(token)
        _ref(observation["declared_tenant_ref"], _TENANT, "Declared tenant")
        _ref(observation["subject_ref"], _SUBJECT, "Subject")
        _ref(observation["resource_ref"], _RESOURCE, "Resource")
        roles = observation["role_refs"]
        if type(roles) is not list or len(roles) > MAX_ROLES_PER_OBSERVATION:
            raise EntraRoleClaimReviewError("Claimed role count is invalid")
        seen: set[str] = set()
        for role in roles:
            role = _ref(role, _ROLE, "Claimed role")
            if role in seen:
                raise EntraRoleClaimReviewError("Duplicate claimed role reference")
            seen.add(role)
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    assigned: dict[tuple[str, str], set[str]] = {}
    for row in plan["assignments"]:
        if row["active"]:
            assigned.setdefault((row["subject_ref"], row["resource_ref"]), set()).add(
                row["role_ref"]
            )
    rows = []
    for observation in plan["observations"]:
        expected = assigned.get((observation["subject_ref"], observation["resource_ref"]), set())
        claimed = set(observation["role_refs"])
        tenant_mismatch = observation["declared_tenant_ref"] != plan["tenant_ref"]
        rows.append(
            {
                "token_ref": observation["token_ref"],
                "declared_tenant_mismatch": tenant_mismatch,
                "comparison_status": (
                    "withheld_tenant_mismatch"
                    if tenant_mismatch
                    else "compared_supplied_direct_assignments"
                ),
                "claimed_without_supplied_direct_assignment": (
                    [] if tenant_mismatch else sorted(claimed - expected)
                ),
                "assigned_but_not_claimed": ([] if tenant_mismatch else sorted(expected - claimed)),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "observations": rows,
        "flags": {
            "tenant_or_subject_authenticated": False,
            "assignment_source_authenticated": False,
            "token_signature_or_issuer_verified": False,
            "claim_configuration_verified": False,
            "effective_access_proven": False,
            "misconfiguration_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Tenant, subject, resource, assignment, and claim labels are caller-supplied.",
            "Only direct active assignments are compared; group grants are not inferred.",
            "No token bytes, issuance chronology, claim mapping, or app authorization is used.",
            "A mismatch does not prove a bad token, misconfiguration, or effective access.",
            "No identity provider, credential, service, network, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "ERC-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class EntraRoleClaimReview:
    """Replay-checked local comparison of supplied opaque labels."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise EntraRoleClaimReviewError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise EntraRoleClaimReviewError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_entra_role_claims(model: Any) -> EntraRoleClaimReview:
    """Compare only supplied direct assignments and opaque claim labels."""
    return EntraRoleClaimReview(_derive(model))


def verify_supplied_entra_role_claims(report: Any, *, model: Any) -> EntraRoleClaimReview:
    """Recompute the report from current supplied model bytes."""
    if type(report) is not EntraRoleClaimReview:
        raise EntraRoleClaimReviewError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise EntraRoleClaimReviewError("Report differs from supplied model replay")
    return EntraRoleClaimReview(expected)
