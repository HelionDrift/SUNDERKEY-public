"""Compare supplied custody approvals with an explicit signer threshold."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "wallet_supplied_signer_threshold_authorization"
PROFILE_ID = "AOE-GB-D10-S06"
CAPABILITY_ID = "army.gb.d10.s06"
VECTOR_ID = "AV-GB-D10-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D10-S06"
WAVE_ID = "IW2-006"
COMMANDER_ID = "AOE-GB-D10-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:b0453c58e9c4858387bd4d7b3c93a89c6aed4783ebb97e8f9d049736fe830997"
DOMAIN = "sunderkey.offline-wallet-threshold-authorization.v1"
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


class WalletThresholdAuthorizationError(ValueError):
    """A supplied custody policy or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "policies"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WalletThresholdAuthorizationError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    policies = core.bounded_list(model["policies"], 16, "policies")
    if not policies:
        raise WalletThresholdAuthorizationError("At least one policy is required")
    seen_policies: set[str] = set()
    for item in policies:
        row = core.exact(
            item, {"policy_id", "threshold", "eligible_signer_ids", "actions"}, "policy"
        )
        policy_id = core.identifier(row["policy_id"], "policy ID")
        if policy_id in seen_policies:
            raise WalletThresholdAuthorizationError("Duplicate policy ID")
        seen_policies.add(policy_id)
        signers = core.bounded_list(row["eligible_signer_ids"], 32, "eligible signers")
        if not signers:
            raise WalletThresholdAuthorizationError("At least one signer is required")
        if any(type(signer) is not str for signer in signers):
            raise WalletThresholdAuthorizationError("Signer IDs must be text")
        for signer in signers:
            core.identifier(signer, "eligible signer ID")
        if len(signers) != len(set(signers)):
            raise WalletThresholdAuthorizationError("Duplicate eligible signer")
        threshold = row["threshold"]
        if type(threshold) is not int or not 1 <= threshold <= len(signers):
            raise WalletThresholdAuthorizationError("Threshold exceeds eligible signers")
        actions = core.bounded_list(row["actions"], 32, "actions")
        if not actions:
            raise WalletThresholdAuthorizationError("At least one action is required")
        seen_actions: set[str] = set()
        for item_action in actions:
            action = core.exact(
                item_action,
                {
                    "action_id",
                    "approval_signer_ids",
                    "declared_authorized",
                    "approvals_complete",
                    "policy_current",
                },
                "action",
            )
            action_id = core.identifier(action["action_id"], "action ID")
            if action_id in seen_actions:
                raise WalletThresholdAuthorizationError("Duplicate action ID")
            seen_actions.add(action_id)
            for key in ("declared_authorized", "approvals_complete", "policy_current"):
                core.boolean(action[key], key)
            approvals = core.bounded_list(action["approval_signer_ids"], 64, "approvals")
            for signer in approvals:
                core.identifier(signer, "approval signer ID")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for policy in model["policies"]:
        eligible = set(policy["eligible_signer_ids"])
        for action in policy["actions"]:
            unique_eligible = eligible.intersection(action["approval_signer_ids"])
            threshold_met = len(unique_eligible) >= policy["threshold"]
            disposition = (
                "unknown"
                if not action["approvals_complete"] or not action["policy_current"]
                else "candidate_declared_authorization_below_threshold"
                if action["declared_authorized"] and not threshold_met
                else "no_declared_below_threshold_authorization"
            )
            projections.append(
                {
                    "policy_id": policy["policy_id"],
                    "action_id": action["action_id"],
                    "threshold": policy["threshold"],
                    "unique_eligible_approval_count": len(unique_eligible),
                    "unknown_signer_ids": sorted(set(action["approval_signer_ids"]) - eligible),
                    "threshold_met": threshold_met,
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
        "policy_count": len(model["policies"]),
        "action_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "signatures_verified": False,
        "wallet_queried": False,
        "custody_effect_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Policy versions, signer identities, approvals and outcomes are caller-supplied.",
            "Repeated approvals from one signer count once; unknown signers do not count.",
            "No signature, account-abstraction, timelock or deployed custody rule is checked.",
            "A threshold mismatch does not prove a wallet action or asset movement.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="WTA-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class WalletThresholdAuthorizationReport:
    """Unsigned custody projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise WalletThresholdAuthorizationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> WalletThresholdAuthorizationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_wallet_threshold(model: Any) -> WalletThresholdAuthorizationReport:
    return WalletThresholdAuthorizationReport._owned(_derive(model))


def verify_supplied_wallet_threshold(
    report: Any, *, model: Any
) -> WalletThresholdAuthorizationReport:
    if type(report) is not WalletThresholdAuthorizationReport:
        raise WalletThresholdAuthorizationError("Exact wallet-threshold wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise WalletThresholdAuthorizationError("Report differs from separate original model")
    return WalletThresholdAuthorizationReport._owned(expected)


def verify_supplied_wallet_threshold_bytes(
    report_bytes: bytes, *, model: Any
) -> WalletThresholdAuthorizationReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise WalletThresholdAuthorizationError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise WalletThresholdAuthorizationError("Exported report differs from original replay")
    return WalletThresholdAuthorizationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-custody-policy",
        "policies": [
            {
                "policy_id": "policy-one",
                "threshold": 2,
                "eligible_signer_ids": ["signer-a", "signer-b", "signer-c"],
                "actions": [
                    {
                        "action_id": "action-one",
                        "approval_signer_ids": ["signer-a", "signer-a"],
                        "declared_authorized": True,
                        "approvals_complete": True,
                        "policy_current": True,
                    },
                    {
                        "action_id": "action-two",
                        "approval_signer_ids": ["signer-a", "signer-b"],
                        "declared_authorized": True,
                        "approvals_complete": True,
                        "policy_current": True,
                    },
                ],
            }
        ],
    }
