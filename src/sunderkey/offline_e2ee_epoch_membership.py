"""Project supplied E2EE epoch membership and envelope coverage offline."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "crypto_supplied_e2ee_epoch_membership"
PROFILE_ID = "AOE-GE-D22-S13"
CAPABILITY_ID = "army.ge.d22.s13"
VECTOR_ID = "AV-GE-D22-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D22-S13"
WAVE_ID = "IW2-026"
COMMANDER_ID = "AOE-GE-D22-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:9868db34db00daebc7c3f29fef5f65d0888d32eab1ca1d5cbc9294029f002ffb"
DOMAIN = "sunderkey.offline-e2ee-epoch-membership.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_EPOCHS = 16
MAX_MEMBERS = 64
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class E2eeEpochMembershipError(ValueError):
    """The supplied epoch model or its original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, tuple[tuple[str, set[str], set[str]], ...], str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "epoch_inventory_complete", "epochs"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise E2eeEpochMembershipError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["epoch_inventory_complete"], "inventory completeness")
    epochs = []
    seen_ids = set()
    for item in core.bounded_list(model["epochs"], MAX_EPOCHS, "epochs"):
        row = core.exact(
            item, {"epoch_id", "member_ids", "envelope_recipient_ids"}, "epoch"
        )
        epoch = core.identifier(row["epoch_id"], "epoch ID")
        if epoch in seen_ids:
            raise E2eeEpochMembershipError("Duplicate epoch ID")
        seen_ids.add(epoch)
        members = [
            core.identifier(member, "member ID")
            for member in core.bounded_list(row["member_ids"], MAX_MEMBERS, "members")
        ]
        recipients = [
            core.identifier(recipient, "recipient ID")
            for recipient in core.bounded_list(
                row["envelope_recipient_ids"], MAX_MEMBERS, "recipients"
            )
        ]
        if not members or len(members) != len(set(members)):
            raise E2eeEpochMembershipError("Member set must be nonempty and unique")
        if len(recipients) != len(set(recipients)):
            raise E2eeEpochMembershipError("Recipient IDs must be unique")
        epochs.append((epoch, set(members), set(recipients)))
    if not epochs:
        raise E2eeEpochMembershipError("At least one epoch is required")
    return model, tuple(epochs), core.canonical(model)


def _derive(value: Any) -> dict:
    model, epochs, source_text = _model(value)
    rows = []
    prior: set[str] = set()
    for index, (epoch, members, recipients) in enumerate(epochs):
        rows.append({
            "epoch_id": epoch,
            "member_count": len(members),
            "envelope_recipient_count": len(recipients),
            "joined_member_ids": sorted(members - prior) if index else [],
            "departed_member_ids": sorted(prior - members) if index else [],
            "members_without_supplied_envelope_ids": sorted(members - recipients),
            "nonmembers_with_supplied_envelope_ids": sorted(recipients - members),
        })
        prior = members
    unknown = [] if model["epoch_inventory_complete"] else ["supplied_epoch_inventory_incomplete"]
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
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "epoch_inventory_complete_asserted": model["epoch_inventory_complete"],
        "supplied_epoch_count": len(epochs),
        "epochs": rows,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_epoch_membership_projection",
        "source_authenticated": False,
        "membership_authenticated": False,
        "envelopes_verified": False,
        "messages_decrypted": False,
        "e2ee_confidentiality_verified": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Epoch order, membership and envelope recipients are supplied assertions.",
            "A missing or excess recipient declaration is not proof of a key-distribution flaw.",
            "No envelope bytes, keys, messages, users or target were observed.",
            "The projection grants no finding, qualification or action authority.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="EEM-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class E2eeEpochMembershipReport:
    """Unsigned epoch projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise E2eeEpochMembershipError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> E2eeEpochMembershipReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_e2ee_epochs(model: Any) -> E2eeEpochMembershipReport:
    return E2eeEpochMembershipReport._owned(_derive(model))


def verify_supplied_e2ee_epochs(
    report: Any, *, model: Any
) -> E2eeEpochMembershipReport:
    if type(report) is not E2eeEpochMembershipReport:
        raise E2eeEpochMembershipError("Exact epoch wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise E2eeEpochMembershipError("Report differs from separate original model")
    return E2eeEpochMembershipReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-e2ee-epochs",
        "epoch_inventory_complete": True,
        "epochs": [
            {"epoch_id": "e1", "member_ids": ["a", "b"], "envelope_recipient_ids": ["a", "b"]},
            {"epoch_id": "e2", "member_ids": ["a", "c"], "envelope_recipient_ids": ["a", "b"]},
        ],
    }
