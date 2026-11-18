"""Project supplied Secure Boot, boot-chain, and update declarations offline."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "secure_boot_supplied_update_chain_projection"
PROFILE_ID = "AOE-GD-D18-S03"
CAPABILITY_ID = "army.gd.d18.s03"
VECTOR_ID = "AV-GD-D18-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S03"
WAVE_ID = "IW2-007"
COMMANDER_ID = "AOE-GD-D18-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:b2fbd0a52c88c0b0d5ddb82dc8b4d9044dbf1207ae3a693cd5117125a6769983"
DOMAIN = "sunderkey.offline-secure-boot-update-chain.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
UINT32_MAX = (1 << 32) - 1
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class SecureBootUpdateChainError(ValueError):
    """The supplied chain model or original-model replay is invalid."""


def _uint32(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= UINT32_MAX:
        raise SecureBootUpdateChainError(f"{label} must be a UINT32")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "chain_complete",
            "expected_secure_boot_enabled", "reported_secure_boot_enabled",
            "boot_chain", "proposed_updates",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SecureBootUpdateChainError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    for field in (
        "chain_complete", "expected_secure_boot_enabled", "reported_secure_boot_enabled"
    ):
        core.boolean(model[field], field)
    chain = core.bounded_list(model["boot_chain"], 64, "boot chain")
    if not chain:
        raise SecureBootUpdateChainError("At least one boot-chain entry is required")
    seen: set[str] = set()
    for entry in chain:
        row = core.exact(
            entry,
            {"artifact_id", "predecessor_id", "declared_loaded", "declared_validation"},
            "boot-chain entry",
        )
        artifact_id = core.identifier(row["artifact_id"], "artifact ID")
        if artifact_id in seen:
            raise SecureBootUpdateChainError("Duplicate boot-chain artifact ID")
        seen.add(artifact_id)
        if row["predecessor_id"] is not None:
            core.identifier(row["predecessor_id"], "predecessor ID")
        core.boolean(row["declared_loaded"], "declared loaded")
        core.choice(
            row["declared_validation"],
            {"accepted", "rejected", "unknown"},
            "declared validation",
        )
    updates = core.bounded_list(model["proposed_updates"], 64, "proposed updates")
    if not updates:
        raise SecureBootUpdateChainError("At least one proposed update is required")
    proposal_ids: set[str] = set()
    for proposal in updates:
        row = core.exact(
            proposal,
            {
                "proposal_id", "target_artifact_id", "current_version",
                "rollback_floor", "proposed_version",
            },
            "proposed update",
        )
        proposal_id = core.identifier(row["proposal_id"], "proposal ID")
        if proposal_id in proposal_ids:
            raise SecureBootUpdateChainError("Duplicate proposal ID")
        proposal_ids.add(proposal_id)
        core.identifier(row["target_artifact_id"], "target artifact ID")
        for field in ("current_version", "rollback_floor", "proposed_version"):
            _uint32(row[field], field)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    reported_enabled = model["reported_secure_boot_enabled"]
    secure_boot_mismatch = (
        model["expected_secure_boot_enabled"] != reported_enabled
    )
    chain_observations = []
    chain_candidate_count = 0
    chain_unknown_count = 0
    prior_id: str | None = None
    artifact_ids: set[str] = set()
    for entry in model["boot_chain"]:
        artifact_id = entry["artifact_id"]
        artifact_ids.add(artifact_id)
        predecessor_consistent = entry["predecessor_id"] == prior_id
        if not predecessor_consistent:
            chain_candidate_count += 1
        validation = entry["declared_validation"]
        if not reported_enabled or not entry["declared_loaded"]:
            validation_disposition = "not_evaluated_for_loaded_secure_boot_image"
        elif validation == "rejected":
            validation_disposition = "candidate_loaded_image_declared_rejected"
            chain_candidate_count += 1
        elif validation == "unknown":
            validation_disposition = "unknown_loaded_image_validation"
            chain_unknown_count += 1
        else:
            validation_disposition = "no_declared_loaded_image_conflict"
        chain_observations.append({
            "artifact_id": artifact_id,
            "predecessor_consistent_with_supplied_order": predecessor_consistent,
            "validation_disposition": validation_disposition,
        })
        prior_id = artifact_id
    update_observations = []
    update_candidate_count = 0
    update_unknown_count = 0
    for proposal in model["proposed_updates"]:
        matches = proposal["target_artifact_id"] in artifact_ids
        proposed_version = proposal["proposed_version"]
        if not matches:
            disposition = "unknown_target_not_in_supplied_chain"
            direction = "unknown"
            update_unknown_count += 1
        else:
            direction = (
                "downgrade" if proposed_version < proposal["current_version"] else
                "same_version" if proposed_version == proposal["current_version"] else
                "upgrade"
            )
            disposition = (
                "candidate_below_declared_rollback_floor"
                if proposed_version < proposal["rollback_floor"] else
                "not_below_declared_rollback_floor"
            )
            update_candidate_count += disposition == "candidate_below_declared_rollback_floor"
        update_observations.append({
            "proposal_id": proposal["proposal_id"],
            "target_matches_supplied_chain": matches,
            "direction_from_supplied_current_version": direction,
            "disposition": disposition,
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "chain_complete_declared": model["chain_complete"],
        "secure_boot_state_disposition": (
            "candidate_declared_policy_state_mismatch"
            if secure_boot_mismatch else "declared_policy_state_matches"
        ),
        "chain_observations": chain_observations,
        "update_observations": update_observations,
        "candidate_count": (
            int(secure_boot_mismatch) + chain_candidate_count + update_candidate_count
        ),
        "unknown_count": (
            int(not model["chain_complete"]) + chain_unknown_count + update_unknown_count
        ),
        "source_authenticated": False,
        "platform_contacted": False,
        "boot_event_log_parsed": False,
        "signature_verified": False,
        "secure_boot_enforcement_proven": False,
        "firmware_update_attempted": False,
        "rollback_enforcement_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "All policy, boot-chain, image-validation and update fields are supplied.",
            "The boot-chain predecessor rule is a local declaration convention.",
            "Declared image validation is not cryptographic signature verification.",
            "Version ordering does not establish actual update or rollback enforcement.",
            "An incomplete chain leaves omitted artifacts unknown even if known mismatches exist.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SBC-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class SecureBootUpdateChainReport:
    """Unsigned declaration projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SecureBootUpdateChainError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SecureBootUpdateChainReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_secure_boot_update_chain(model: Any) -> SecureBootUpdateChainReport:
    return SecureBootUpdateChainReport._owned(_derive(model))


def verify_supplied_secure_boot_update_chain(
    report: Any, *, model: Any
) -> SecureBootUpdateChainReport:
    if type(report) is not SecureBootUpdateChainReport:
        raise SecureBootUpdateChainError("Exact Secure Boot update-chain wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise SecureBootUpdateChainError("Report differs from separate original model")
    return SecureBootUpdateChainReport._owned(expected)


def verify_supplied_secure_boot_update_chain_bytes(
    report_bytes: bytes, *, model: Any
) -> SecureBootUpdateChainReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise SecureBootUpdateChainError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise SecureBootUpdateChainError("Exported report differs from original replay")
    return SecureBootUpdateChainReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-secure-boot-chain",
        "chain_complete": True,
        "expected_secure_boot_enabled": True,
        "reported_secure_boot_enabled": True,
        "boot_chain": [
            {
                "artifact_id": "boot-manager",
                "predecessor_id": None,
                "declared_loaded": True,
                "declared_validation": "accepted",
            },
            {
                "artifact_id": "os-loader",
                "predecessor_id": "boot-manager",
                "declared_loaded": True,
                "declared_validation": "accepted",
            },
        ],
        "proposed_updates": [
            {
                "proposal_id": "example-below-floor",
                "target_artifact_id": "boot-manager",
                "current_version": 12,
                "rollback_floor": 9,
                "proposed_version": 8,
            }
        ],
    }
