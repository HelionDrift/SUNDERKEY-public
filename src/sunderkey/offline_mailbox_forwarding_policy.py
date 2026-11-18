"""Compare synthetic mailbox-forwarding declarations with supplied policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "windows_supplied_mailbox_forwarding_policy_projection"
PROFILE_ID = "AOE-GC-D11-S15"
CAPABILITY_ID = "army.gc.d11.s15"
VECTOR_ID = "AV-GC-D11-S15-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S15"
WAVE_ID = "IW2-015"
COMMANDER_ID = "AOE-GC-D11-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:ffbafddb0b08190ab621cc4b43fc4624f8c7f88968a40c4d1992f8e06eefd98d"
DOMAIN = "sunderkey.offline-mailbox-forwarding-policy.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class MailboxForwardingPolicyError(ValueError):
    """A supplied forwarding model or original-model replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "policies", "mailboxes",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MailboxForwardingPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise MailboxForwardingPolicyError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    policies = {}
    for item in core.bounded_list(model["policies"], 32, "policies"):
        row = core.exact(item, {
            "policy_id", "external_forward_allowed", "allowed_destination_domain_ids",
        }, "policy")
        policy_id = core.identifier(row["policy_id"], "policy ID")
        if policy_id in policies:
            raise MailboxForwardingPolicyError("Duplicate policy ID")
        domains = [
            core.identifier(domain, "destination domain ID")
            for domain in core.bounded_list(
                row["allowed_destination_domain_ids"], 32, "allowed domains"
            )
        ]
        if len(domains) != len(set(domains)):
            raise MailboxForwardingPolicyError("Duplicate allowed domain ID")
        policies[policy_id] = {
            "allowed": core.boolean(row["external_forward_allowed"], "external forward policy"),
            "domains": set(domains),
        }
    if not policies:
        raise MailboxForwardingPolicyError("At least one policy is required")
    mailboxes = core.bounded_list(model["mailboxes"], 64, "mailboxes")
    if not mailboxes:
        raise MailboxForwardingPolicyError("At least one mailbox is required")
    rows = []
    seen = set()
    for item in mailboxes:
        row = core.exact(item, {
            "mailbox_id", "policy_id", "external_forward_declared",
            "destination_domain_id",
        }, "mailbox")
        mailbox_id = core.identifier(row["mailbox_id"], "mailbox ID")
        policy_id = core.identifier(row["policy_id"], "policy ID")
        if mailbox_id in seen or policy_id not in policies:
            raise MailboxForwardingPolicyError("Duplicate mailbox or unknown policy")
        seen.add(mailbox_id)
        forward = core.boolean(row["external_forward_declared"], "forward declaration")
        destination = row["destination_domain_id"]
        if forward:
            if destination is None:
                raise MailboxForwardingPolicyError("Active forwarding requires destination")
            destination = core.identifier(destination, "destination domain ID")
        elif destination is not None:
            raise MailboxForwardingPolicyError("Inactive forwarding cannot name destination")
        flags = []
        if forward and not policies[policy_id]["allowed"]:
            flags.append("external_forward_outside_supplied_policy")
        if forward and destination not in policies[policy_id]["domains"]:
            flags.append("destination_outside_supplied_policy")
        rows.append({
            "mailbox_id": mailbox_id,
            "policy_id": policy_id,
            "external_forward_declared": forward,
            "destination_domain_id": destination,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["mailbox_id"])
    deviations = [row["mailbox_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_mailbox_inventory_incomplete"]
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
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "inventory_complete_asserted": complete,
        "mailbox_projections": rows,
        "declared_policy_deviation_mailbox_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_mailbox_forwarding_projection",
        "source_authenticated": False,
        "tenant_connected": False,
        "mailbox_content_read": False,
        "forwarding_setting_verified": False,
        "message_sent": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Mailboxes, forwarding, destination labels, policy, and completeness are assertions.",
            "The model does not parse or verify Exchange Online tenant configuration.",
            "A declared mismatch does not prove delivered mail or data exposure.",
            "No tenant, mailbox, message, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MFP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class MailboxForwardingPolicyReport:
    """Unsigned forwarding projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MailboxForwardingPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MailboxForwardingPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_mailbox_forwarding(model: Any) -> MailboxForwardingPolicyReport:
    return MailboxForwardingPolicyReport._owned(_derive(model))


def verify_supplied_mailbox_forwarding(
    report: Any, *, model: Any
) -> MailboxForwardingPolicyReport:
    if type(report) is not MailboxForwardingPolicyReport:
        raise MailboxForwardingPolicyError("Exact mailbox wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MailboxForwardingPolicyError("Report differs from separate original model")
    return MailboxForwardingPolicyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-mailbox-forwarding",
        "synthetic_fixture": True, "inventory_complete": True,
        "policies": [{
            "policy_id": "restricted", "external_forward_allowed": False,
            "allowed_destination_domain_ids": [],
        }],
        "mailboxes": [{
            "mailbox_id": "mailbox-a", "policy_id": "restricted",
            "external_forward_declared": True,
            "destination_domain_id": "external-example",
        }],
    }
