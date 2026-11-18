"""Compare supplied agent credential uses with declared scope and time bounds."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "agent_supplied_credential_boundary"
PROFILE_ID = "AOE-GD-D20-S15"
CAPABILITY_ID = "army.gd.d20.s15"
VECTOR_ID = "AV-GD-D20-S15-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S15"
WAVE_ID = "IW2-005"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:dfd1426eade789cf98704bd5927013b845ca19c53e1c82814279a114d2b08be3"
DOMAIN = "sunderkey.offline-agent-credential-boundary.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_EPOCH = 4_102_444_800
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class AgentCredentialBoundaryError(ValueError):
    """A supplied credential declaration or replay is invalid."""


def _ids(value: Any, label: str, maximum: int, *, allow_empty: bool = False) -> list[str]:
    rows = core.bounded_list(value, maximum, label)
    if not rows and not allow_empty:
        raise AgentCredentialBoundaryError(f"{label} must not be empty")
    result = [core.identifier(item, label) for item in rows]
    if len(set(result)) != len(result):
        raise AgentCredentialBoundaryError(f"{label} has duplicate identifiers")
    return result


def _epoch(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_EPOCH:
        raise AgentCredentialBoundaryError(f"{label} must be a bounded native epoch integer")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "credentials", "uses"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AgentCredentialBoundaryError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    credentials = core.bounded_list(model["credentials"], 32, "credentials")
    if not credentials:
        raise AgentCredentialBoundaryError("Credentials must not be empty")
    ids: set[str] = set()
    for item in credentials:
        row = core.exact(
            item,
            {
                "credential_id", "approved_agent_ids", "audiences", "scopes",
                "status", "expires_at_epoch",
            },
            "credential",
        )
        credential_id = core.identifier(row["credential_id"], "credential ID")
        if credential_id in ids:
            raise AgentCredentialBoundaryError("Duplicate credential ID")
        ids.add(credential_id)
        _ids(row["approved_agent_ids"], "approved agent IDs", 16)
        _ids(row["audiences"], "audiences", 16)
        _ids(row["scopes"], "scopes", 32)
        core.choice(row["status"], {"active", "revoked", "unknown"}, "status")
        if row["expires_at_epoch"] != "unknown":
            _epoch(row["expires_at_epoch"], "expiration")
    uses = core.bounded_list(model["uses"], 128, "uses")
    if not uses:
        raise AgentCredentialBoundaryError("Uses must not be empty")
    seen_uses: set[str] = set()
    for item in uses:
        row = core.exact(
            item,
            {
                "use_id", "credential_id", "agent_id", "audience",
                "required_scopes", "invocation_epoch", "context_complete",
            },
            "credential use",
        )
        use_id = core.identifier(row["use_id"], "use ID")
        if use_id in seen_uses:
            raise AgentCredentialBoundaryError("Duplicate use ID")
        seen_uses.add(use_id)
        if core.identifier(row["credential_id"], "use credential ID") not in ids:
            raise AgentCredentialBoundaryError("Use references an absent credential")
        core.identifier(row["agent_id"], "agent ID")
        core.identifier(row["audience"], "audience")
        _ids(row["required_scopes"], "required scopes", 32, allow_empty=True)
        _epoch(row["invocation_epoch"], "invocation")
        core.boolean(row["context_complete"], "context completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    credentials = {item["credential_id"]: item for item in model["credentials"]}
    projections = []
    for item in model["uses"]:
        credential = credentials[item["credential_id"]]
        reasons: list[str] = []
        if (
            not item["context_complete"]
            or credential["status"] == "unknown"
            or credential["expires_at_epoch"] == "unknown"
        ):
            disposition = "unknown"
        else:
            if credential["status"] == "revoked":
                reasons.append("declared_revoked")
            if item["agent_id"] not in credential["approved_agent_ids"]:
                reasons.append("agent_not_approved")
            if item["audience"] not in credential["audiences"]:
                reasons.append("audience_not_allowed")
            if not set(item["required_scopes"]).issubset(credential["scopes"]):
                reasons.append("required_scope_missing")
            if item["invocation_epoch"] >= credential["expires_at_epoch"]:
                reasons.append("declared_expired")
            disposition = (
                "candidate_declared_credential_boundary"
                if reasons else "within_declared_bounds_unverified"
            )
        projections.append({
            "use_id": item["use_id"],
            "credential_id": item["credential_id"],
            "disposition": disposition,
            "risk_reasons": reasons,
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "use_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "secret_value_decoding_performed": False,
        "credential_use_performed": False,
        "source_authenticated": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Credential references, grants, status and use events are caller declarations.",
            "Opaque identifier fields cannot prove that a caller omitted disguised secrets.",
            "No token, key, secret, provider, agent or target is accessed.",
            "Time comparison uses supplied epoch seconds and no current clock.",
            "A candidate is a declared boundary mismatch, not observed credential abuse.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="ACB-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class AgentCredentialBoundaryReport:
    """Unsigned projection requiring a separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise AgentCredentialBoundaryError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> AgentCredentialBoundaryReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_agent_credential_boundary(model: Any) -> AgentCredentialBoundaryReport:
    return AgentCredentialBoundaryReport._owned(_derive(model))


def verify_supplied_agent_credential_boundary(
    report: Any, *, model: Any
) -> AgentCredentialBoundaryReport:
    if type(report) is not AgentCredentialBoundaryReport:
        raise AgentCredentialBoundaryError("Exact credential-boundary wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise AgentCredentialBoundaryError("Report differs from separate original model")
    return AgentCredentialBoundaryReport._owned(expected)


def verify_supplied_agent_credential_boundary_bytes(
    report_bytes: bytes, *, model: Any
) -> AgentCredentialBoundaryReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise AgentCredentialBoundaryError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise AgentCredentialBoundaryError("Exported report differs from original replay")
    return AgentCredentialBoundaryReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-agent-credential-boundary",
        "credentials": [
            {
                "credential_id": "ref-primary",
                "approved_agent_ids": ["agent-one"],
                "audiences": ["service-one"],
                "scopes": ["read", "write"],
                "status": "active",
                "expires_at_epoch": 100,
            },
            {
                "credential_id": "ref-unknown",
                "approved_agent_ids": ["agent-one"],
                "audiences": ["service-one"],
                "scopes": ["read"],
                "status": "unknown",
                "expires_at_epoch": "unknown",
            },
        ],
        "uses": [
            {
                "use_id": "within", "credential_id": "ref-primary",
                "agent_id": "agent-one", "audience": "service-one",
                "required_scopes": ["read"], "invocation_epoch": 50,
                "context_complete": True,
            },
            {
                "use_id": "audience-mismatch", "credential_id": "ref-primary",
                "agent_id": "agent-one", "audience": "service-two",
                "required_scopes": ["read"], "invocation_epoch": 50,
                "context_complete": True,
            },
            {
                "use_id": "scope-missing", "credential_id": "ref-primary",
                "agent_id": "agent-one", "audience": "service-one",
                "required_scopes": ["admin"], "invocation_epoch": 50,
                "context_complete": True,
            },
            {
                "use_id": "agent-mismatch", "credential_id": "ref-primary",
                "agent_id": "agent-two", "audience": "service-one",
                "required_scopes": ["read"], "invocation_epoch": 50,
                "context_complete": True,
            },
            {
                "use_id": "expired", "credential_id": "ref-primary",
                "agent_id": "agent-one", "audience": "service-one",
                "required_scopes": ["read"], "invocation_epoch": 100,
                "context_complete": True,
            },
            {
                "use_id": "unknown", "credential_id": "ref-unknown",
                "agent_id": "agent-one", "audience": "service-one",
                "required_scopes": ["read"], "invocation_epoch": 50,
                "context_complete": True,
            },
        ],
    }
