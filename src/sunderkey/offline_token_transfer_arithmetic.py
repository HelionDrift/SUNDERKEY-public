"""Reconcile supplied zero-fee token transfers against balance arithmetic."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "token_supplied_zero_fee_transfer_arithmetic"
PROFILE_ID = "AOE-GB-D10-S09"
CAPABILITY_ID = "army.gb.d10.s09"
VECTOR_ID = "AV-GB-D10-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D10-S09"
WAVE_ID = "IW2-009"
COMMANDER_ID = "AOE-GB-D10-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:b58dff123816bfbe9b8877853df78992b5e1ed53abe9eada0ca0b8dca7d6d65d"
DOMAIN = "sunderkey.offline-token-transfer-arithmetic.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_UNITS = 1_000_000_000_000
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


class TokenTransferArithmeticError(ValueError):
    """A supplied transfer ledger or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "asset_id", "transfers"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise TokenTransferArithmeticError("Unsupported model version")
    for key in ("source_id", "asset_id"):
        core.identifier(model[key], key)
    transfers = core.bounded_list(model["transfers"], 32, "transfers")
    if not transfers:
        raise TokenTransferArithmeticError("At least one transfer is required")
    seen: set[str] = set()
    for item in transfers:
        row = core.exact(
            item,
            {
                "transfer_id",
                "sender_id",
                "recipient_id",
                "amount_units",
                "sender_before_units",
                "sender_after_units",
                "recipient_before_units",
                "recipient_after_units",
                "declared_success",
                "context_complete",
            },
            "transfer",
        )
        transfer_id = core.identifier(row["transfer_id"], "transfer ID")
        if transfer_id in seen:
            raise TokenTransferArithmeticError("Duplicate transfer ID")
        seen.add(transfer_id)
        sender = core.identifier(row["sender_id"], "sender ID")
        recipient = core.identifier(row["recipient_id"], "recipient ID")
        if sender == recipient:
            raise TokenTransferArithmeticError("Self transfers require a separate model")
        for key in (
            "amount_units",
            "sender_before_units",
            "sender_after_units",
            "recipient_before_units",
            "recipient_after_units",
        ):
            amount = row[key]
            if type(amount) is not int or not 0 <= amount <= MAX_UNITS:
                raise TokenTransferArithmeticError("Token amounts must be bounded integers")
        core.boolean(row["declared_success"], "declared success")
        core.boolean(row["context_complete"], "context completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for row in model["transfers"]:
        amount = row["amount_units"]
        sender_expected = row["sender_before_units"] - amount
        recipient_expected = row["recipient_before_units"] + amount
        sender_matches = sender_expected >= 0 and row["sender_after_units"] == sender_expected
        recipient_matches = (
            recipient_expected <= MAX_UNITS and row["recipient_after_units"] == recipient_expected
        )
        disposition = (
            "unknown"
            if not row["context_complete"]
            else "candidate_declared_zero_fee_transfer_balance_mismatch"
            if row["declared_success"] and not (sender_matches and recipient_matches)
            else "no_declared_successful_transfer_mismatch"
        )
        projections.append(
            {
                "transfer_id": row["transfer_id"],
                "sender_expected_after_units": sender_expected,
                "recipient_expected_after_units": recipient_expected,
                "sender_matches": sender_matches,
                "recipient_matches": recipient_matches,
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
        "asset_id": model["asset_id"],
        "transfer_count": len(model["transfers"]),
        "transfer_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "token_contract_queried": False,
        "transfer_executed": False,
        "supply_conservation_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Balances, success flags, account identities and fee assumptions are caller-supplied.",
            "Only isolated zero-fee, two-account arithmetic is compared.",
            "Minting, burning, rebasing, fees, hooks, simultaneous transfers and "
            "supply are omitted.",
            "A mismatch does not prove on-chain execution or token loss.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="TTA-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class TokenTransferArithmeticReport:
    """Unsigned transfer projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise TokenTransferArithmeticError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> TokenTransferArithmeticReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_token_transfers(model: Any) -> TokenTransferArithmeticReport:
    return TokenTransferArithmeticReport._owned(_derive(model))


def verify_supplied_token_transfers(report: Any, *, model: Any) -> TokenTransferArithmeticReport:
    if type(report) is not TokenTransferArithmeticReport:
        raise TokenTransferArithmeticError("Exact token-transfer wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise TokenTransferArithmeticError("Report differs from separate original model")
    return TokenTransferArithmeticReport._owned(expected)


def verify_supplied_token_transfers_bytes(
    report_bytes: bytes, *, model: Any
) -> TokenTransferArithmeticReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise TokenTransferArithmeticError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise TokenTransferArithmeticError("Exported report differs from original replay")
    return TokenTransferArithmeticReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-token-balances",
        "asset_id": "token-one",
        "transfers": [
            {
                "transfer_id": "transfer-one",
                "sender_id": "account-a",
                "recipient_id": "account-b",
                "amount_units": 20,
                "sender_before_units": 100,
                "sender_after_units": 75,
                "recipient_before_units": 20,
                "recipient_after_units": 40,
                "declared_success": True,
                "context_complete": True,
            },
            {
                "transfer_id": "transfer-two",
                "sender_id": "account-c",
                "recipient_id": "account-d",
                "amount_units": 10,
                "sender_before_units": 30,
                "sender_after_units": 20,
                "recipient_before_units": 5,
                "recipient_after_units": 15,
                "declared_success": True,
                "context_complete": True,
            },
        ],
    }
