"""Compare bounded, caller-supplied Kerberos AD service declarations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "supplied_kerberos_ad_declarations"
PROFILE_ID = "AOE-GC-D11-S02"
CAPABILITY_ID = "army.gc.d11.s02"
VECTOR_ID = "AV-GC-D11-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S02"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GC-D11-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:3b15bb5e95c4d39ef681101acfb07d6b5a2eb7678fca2e9e5fb2cbbf768d0b39"
DOMAIN = "sunderkey.offline-kerberos-ad-declarations.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
REF = re.compile(r"(?:service|account|spn):sha256:[0-9a-f]{64}\Z")
ENCRYPTION_LABELS = {"aes128", "aes256", "rc4", "other"}
DELEGATION_MODES = {"none", "constrained", "unconstrained"}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class KerberosAdDeclarationsError(ValueError):
    """The supplied declaration model or replay comparison is invalid."""


def _ref(value: Any, kind: str) -> str:
    if type(value) is not str or REF.fullmatch(value) is None or not value.startswith(kind + ":"):
        raise KerberosAdDeclarationsError(f"{kind} reference must be an opaque digest")
    return value


def _refs(value: Any, kind: str, maximum: int) -> list[str]:
    refs = core.bounded_list(value, maximum, kind + " references")
    for item in refs:
        _ref(item, kind)
    if len(refs) != len(set(refs)):
        raise KerberosAdDeclarationsError("Duplicate " + kind + " reference")
    return refs


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "policy", "services"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise KerberosAdDeclarationsError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    policy = core.exact(
        model["policy"],
        {"forbid_unconstrained_delegation", "allowed_encryption_labels"},
        "policy",
    )
    core.boolean(policy["forbid_unconstrained_delegation"], "delegation policy")
    allowed = core.bounded_list(policy["allowed_encryption_labels"], 4, "allowed encryption")
    if not allowed or len(allowed) != len(set(allowed)):
        raise KerberosAdDeclarationsError("Allowed encryption labels must be nonempty and unique")
    for label in allowed:
        core.choice(label, ENCRYPTION_LABELS, "encryption label")
    services = core.bounded_list(model["services"], 64, "services")
    if not services:
        raise KerberosAdDeclarationsError("At least one service declaration is required")
    seen_services: set[str] = set()
    for item in services:
        service = core.exact(
            item,
            {"service_ref", "account_ref", "spn_refs", "delegation_mode",
             "delegation_target_refs", "encryption_labels"},
            "service",
        )
        service_ref = _ref(service["service_ref"], "service")
        if service_ref in seen_services:
            raise KerberosAdDeclarationsError("Duplicate service declaration")
        seen_services.add(service_ref)
        _ref(service["account_ref"], "account")
        if not _refs(service["spn_refs"], "spn", 16):
            raise KerberosAdDeclarationsError("Service requires a supplied SPN reference")
        mode = core.choice(service["delegation_mode"], DELEGATION_MODES, "delegation mode")
        targets = _refs(service["delegation_target_refs"], "service", 16)
        if mode != "constrained" and targets:
            raise KerberosAdDeclarationsError("Delegation targets require constrained mode")
        encryptions = core.bounded_list(service["encryption_labels"], 4, "encryptions")
        if not encryptions or len(encryptions) != len(set(encryptions)):
            raise KerberosAdDeclarationsError("Encryption labels must be nonempty and unique")
        for label in encryptions:
            core.choice(label, ENCRYPTION_LABELS, "encryption label")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    complete = model["inventory_complete"]
    policy = model["policy"]
    spn_accounts: dict[str, set[str]] = {}
    for service in model["services"]:
        for spn in service["spn_refs"]:
            spn_accounts.setdefault(spn, set()).add(service["account_ref"])
    rows: list[dict] = []
    candidates: list[dict] = []
    for service in model["services"]:
        issues: list[str] = []
        if any(len(spn_accounts[spn]) > 1 for spn in service["spn_refs"]):
            issues.append("spn_declared_for_multiple_accounts")
        if (
            policy["forbid_unconstrained_delegation"]
            and service["delegation_mode"] == "unconstrained"
        ):
            issues.append("unconstrained_delegation_outside_supplied_policy")
        if service["delegation_mode"] == "constrained" and not service["delegation_target_refs"]:
            issues.append("constrained_delegation_without_supplied_targets")
        if set(service["encryption_labels"]) - set(policy["allowed_encryption_labels"]):
            issues.append("encryption_label_outside_supplied_policy")
        row = {
            "service_ref": service["service_ref"],
            "policy_issues": issues if complete else None,
            "row_disposition": "evaluated" if complete else "unknown_incomplete_inventory",
        }
        rows.append(row)
        if complete and issues:
            candidates.append({"service_ref": service["service_ref"], "policy_issues": issues})
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "service_count": len(rows),
        "rows": rows,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "unknown_count": len(rows) if not complete else 0,
        "disposition": "unknown" if not complete else (
            "candidate_supplied_declaration_mismatch"
            if candidates else "supplied_declarations_match"
        ),
        "directory_state_authenticated": False,
        "ticket_or_authentication_observed": False,
        "effective_access_or_exploitability_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "All service, SPN, account, policy and completeness declarations are caller-supplied.",
            "Labels are compared only within this closed local model; "
            "AD semantics are not evaluated.",
            "No tickets, credentials, directory services, network or target are contacted.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="KAD-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class KerberosAdDeclarationsReport:
    """Unsigned projection requiring replay from the original model."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise KerberosAdDeclarationsError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> KerberosAdDeclarationsReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_kerberos_ad(model: Any) -> KerberosAdDeclarationsReport:
    return KerberosAdDeclarationsReport._owned(_derive(model))


def verify_supplied_kerberos_ad(
    report: Any, *, model: Any
) -> KerberosAdDeclarationsReport:
    if type(report) is not KerberosAdDeclarationsReport:
        raise KerberosAdDeclarationsError("Exact Kerberos AD report wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise KerberosAdDeclarationsError("Report differs from original-model replay")
    return KerberosAdDeclarationsReport._owned(expected)


def verify_supplied_kerberos_ad_bytes(
    report_bytes: bytes, *, model: Any
) -> KerberosAdDeclarationsReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    expected = _derive(model)
    if type(report) is not dict or core.canonical(report) != core.canonical(expected):
        raise KerberosAdDeclarationsError("Exported report differs from original-model replay")
    return KerberosAdDeclarationsReport._owned(expected)


def component_fixture() -> dict:
    service_a = "service:sha256:" + "a" * 64
    service_b = "service:sha256:" + "b" * 64
    account_a = "account:sha256:" + "c" * 64
    account_b = "account:sha256:" + "d" * 64
    spn = "spn:sha256:" + "e" * 64
    return {
        "schema_version": 1,
        "source_id": "synthetic-kerberos-ad",
        "inventory_complete": True,
        "policy": {
            "forbid_unconstrained_delegation": True,
            "allowed_encryption_labels": ["aes128", "aes256"],
        },
        "services": [
            {"service_ref": service_a, "account_ref": account_a, "spn_refs": [spn],
             "delegation_mode": "unconstrained", "delegation_target_refs": [],
             "encryption_labels": ["aes256", "rc4"]},
            {"service_ref": service_b, "account_ref": account_b, "spn_refs": [spn],
             "delegation_mode": "none", "delegation_target_refs": [],
             "encryption_labels": ["aes256"]},
        ],
    }
