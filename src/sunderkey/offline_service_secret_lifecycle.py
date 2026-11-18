"""Project negative service-secret lifecycle invariants from synthetic metadata."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "identity_supplied_service_secret_lifecycle"
PROFILE_ID = "AOE-GA-D03-S11"
CAPABILITY_ID = "army.ga.d03.s11"
VECTOR_ID = "AV-GA-D03-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D03-S11"
WAVE_ID = "IW2-012"
COMMANDER_ID = "AOE-GA-D03-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:42cf1574b1595e9c3de2a4071a1e9fa31be9cb98cfbc76f858980f1e5e3464dc"
DOMAIN = "sunderkey.offline-service-secret-lifecycle.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_ACCOUNTS = 128
MAX_SECRETS = 256
MAX_OBSERVATIONS = 512
MAX_TICK = 1_000_000_000
SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class ServiceSecretLifecycleError(ValueError):
    """A supplied lifecycle model or separately sourced replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise ServiceSecretLifecycleError(f"{label} must be a synthetic label")
    return identifier


def _tick(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_TICK:
        raise ServiceSecretLifecycleError(f"{label} must be a bounded logical tick")
    return value


def _model(value: Any) -> tuple[dict, dict[str, dict], dict[str, dict]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "policy_complete", "order_complete",
            "accounts", "secrets", "observations",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ServiceSecretLifecycleError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    core.boolean(model["policy_complete"], "policy completeness")
    core.boolean(model["order_complete"], "order completeness")
    accounts: dict[str, dict] = {}
    for item in core.bounded_list(model["accounts"], MAX_ACCOUNTS, "accounts"):
        row = core.exact(item, {"account_id", "maximum_age_ticks"}, "account")
        account_id = _synthetic(row["account_id"], "account ID")
        if account_id in accounts:
            raise ServiceSecretLifecycleError("Duplicate account ID")
        maximum_age = _tick(row["maximum_age_ticks"], "maximum secret age")
        if maximum_age == 0:
            raise ServiceSecretLifecycleError("Maximum secret age must be positive")
        accounts[account_id] = row
    secrets: dict[str, dict] = {}
    for item in core.bounded_list(model["secrets"], MAX_SECRETS, "secrets"):
        row = core.exact(
            item,
            {"secret_id", "account_id", "issued_at", "expires_at", "revoked_at"},
            "secret metadata",
        )
        secret_id = _synthetic(row["secret_id"], "secret ID")
        account_id = _synthetic(row["account_id"], "secret account ID")
        if secret_id in secrets or account_id not in accounts:
            raise ServiceSecretLifecycleError("Secret is duplicated or has no account")
        issued = _tick(row["issued_at"], "issuance tick")
        if row["expires_at"] is not None:
            expiration = _tick(row["expires_at"], "expiration tick")
            if expiration <= issued:
                raise ServiceSecretLifecycleError("Expiration must follow issuance")
        if row["revoked_at"] is not None:
            revocation = _tick(row["revoked_at"], "revocation tick")
            if revocation < issued:
                raise ServiceSecretLifecycleError("Revocation precedes issuance")
        secrets[secret_id] = row
    observations = core.bounded_list(model["observations"], MAX_OBSERVATIONS, "observations")
    if not observations:
        raise ServiceSecretLifecycleError("At least one observation is required")
    seen_observations: set[str] = set()
    for item in observations:
        row = core.exact(
            item,
            {"observation_id", "secret_id", "at_tick", "reported_outcome"},
            "observation",
        )
        observation_id = _synthetic(row["observation_id"], "observation ID")
        if observation_id in seen_observations:
            raise ServiceSecretLifecycleError("Duplicate observation ID")
        seen_observations.add(observation_id)
        _synthetic(row["secret_id"], "observation secret ID")
        _tick(row["at_tick"], "observation tick")
        core.choice(row["reported_outcome"], {"allowed", "denied", "unknown"}, "outcome")
    return model, accounts, secrets


def _project(observation: dict, model: dict, accounts: dict, secrets: dict) -> dict:
    secret = secrets.get(observation["secret_id"])
    tick = observation["at_tick"]
    if not model["policy_complete"] or not model["order_complete"]:
        decision, basis = "unknown", "incomplete_policy_or_order"
    elif secret is None:
        decision, basis = "unknown", "unknown_secret_metadata"
    elif tick < secret["issued_at"]:
        decision, basis = "deny", "before_declared_issuance"
    elif secret["revoked_at"] is not None and tick >= secret["revoked_at"]:
        decision, basis = "deny", "after_declared_revocation"
    elif secret["expires_at"] is not None and tick >= secret["expires_at"]:
        decision, basis = "deny", "after_declared_expiration"
    elif tick - secret["issued_at"] > accounts[secret["account_id"]]["maximum_age_ticks"]:
        decision, basis = "deny", "beyond_declared_rotation_age"
    else:
        decision, basis = "unknown", "no_negative_invariant"
    reported = observation["reported_outcome"]
    if decision == "unknown" or reported == "unknown":
        assessment = "unknown"
    elif reported == "allowed":
        assessment = "candidate_declared_stale_secret_use"
    else:
        assessment = "declared_deny_consistent"
    return {
        "observation_id": observation["observation_id"],
        "secret_id": observation["secret_id"],
        "at_tick": tick,
        "reported_outcome": reported,
        "projected_decision": decision,
        "basis": basis,
        "assessment": assessment,
    }


def _derive(value: Any) -> dict:
    model, accounts, secrets = _model(value)
    projections = [
        _project(item, model, accounts, secrets) for item in model["observations"]
    ]
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model": model,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "projections": projections,
        "summary": {
            "observation_count": len(projections),
            "candidate_count": sum(
                row["assessment"] == "candidate_declared_stale_secret_use"
                for row in projections
            ),
            "unknown_count": sum(row["assessment"] == "unknown" for row in projections),
        },
        "source_authenticated": False,
        "account_policy_authenticated": False,
        "secret_metadata_authenticated": False,
        "reported_outcomes_authenticated": False,
        "credential_value_processed": False,
        "effective_access_observed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Account policy, secret metadata, ordering and outcomes are caller declarations.",
            "Secret IDs are synthetic references, never credential values or fingerprints.",
            "Only negative lifecycle invariants are modeled; valid access is never inferred.",
            "A candidate mismatch is not secret use, effective access or a vulnerability.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SSL-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class ServiceSecretLifecycleReport:
    """Unsigned report wrapper that requires separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ServiceSecretLifecycleError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ServiceSecretLifecycleReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_service_secret_lifecycle(model: Any) -> ServiceSecretLifecycleReport:
    try:
        return ServiceSecretLifecycleReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise ServiceSecretLifecycleError(str(exc)) from exc


def verify_supplied_service_secret_lifecycle(
    report: Any, *, model: Any,
) -> ServiceSecretLifecycleReport:
    if type(report) is not ServiceSecretLifecycleReport:
        raise ServiceSecretLifecycleError("Exact report wrapper required")
    expected = analyze_supplied_service_secret_lifecycle(model)
    if report.to_json() != expected.to_json():
        raise ServiceSecretLifecycleError("Report differs from separate original model")
    return expected


def verify_supplied_service_secret_lifecycle_bytes(
    report_bytes: bytes, *, model: Any,
) -> ServiceSecretLifecycleReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise ServiceSecretLifecycleError(str(exc)) from exc
    expected = analyze_supplied_service_secret_lifecycle(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise ServiceSecretLifecycleError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:service-secrets",
        "policy_complete": True,
        "order_complete": True,
        "accounts": [
            {"account_id": "synthetic:service-one", "maximum_age_ticks": 20},
        ],
        "secrets": [
            {
                "secret_id": "synthetic:secret-one",
                "account_id": "synthetic:service-one",
                "issued_at": 10,
                "expires_at": 50,
                "revoked_at": 40,
            },
        ],
        "observations": [
            {
                "observation_id": "synthetic:early-use",
                "secret_id": "synthetic:secret-one",
                "at_tick": 15,
                "reported_outcome": "allowed",
            },
            {
                "observation_id": "synthetic:stale-use",
                "secret_id": "synthetic:secret-one",
                "at_tick": 35,
                "reported_outcome": "allowed",
            },
        ],
    }


__all__ = [
    "ServiceSecretLifecycleError", "ServiceSecretLifecycleReport",
    "analyze_supplied_service_secret_lifecycle", "verify_supplied_service_secret_lifecycle",
    "verify_supplied_service_secret_lifecycle_bytes", "component_fixture",
]
