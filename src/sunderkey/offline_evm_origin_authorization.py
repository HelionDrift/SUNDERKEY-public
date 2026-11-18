"""Review supplied EVM origin and immediate-caller authorization labels."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "evm_supplied_origin_authorization_boundary"
PROFILE_ID = "AOE-GB-D10-S01"
CAPABILITY_ID = "army.gb.d10.s01"
VECTOR_ID = "AV-GB-D10-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D10-S01"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GB-D10-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:699ceb0a13c80ef96604468afb084b574446c0da982f153ccb113e730a09324"
DOMAIN = "sunderkey.offline-evm-origin-authorization.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
SOURCES = {"transaction_origin", "immediate_caller", "explicit_actor"}
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


class EvmOriginAuthorizationError(ValueError):
    """A supplied EVM authorization model or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "checks"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise EvmOriginAuthorizationError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    checks = core.bounded_list(model["checks"], 32, "checks")
    if not checks:
        raise EvmOriginAuthorizationError("At least one check is required")
    seen: set[str] = set()
    for item in checks:
        row = core.exact(
            item,
            {
                "check_id",
                "contract_id",
                "transaction_origin_id",
                "immediate_caller_id",
                "authorization_source",
                "declared_authorized",
                "context_complete",
            },
            "check",
        )
        check_id = core.identifier(row["check_id"], "check ID")
        if check_id in seen:
            raise EvmOriginAuthorizationError("Duplicate check ID")
        seen.add(check_id)
        for key in ("contract_id", "transaction_origin_id", "immediate_caller_id"):
            core.identifier(row[key], key)
        core.choice(row["authorization_source"], SOURCES, "authorization source")
        core.boolean(row["declared_authorized"], "declared authorization")
        core.boolean(row["context_complete"], "context completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for row in model["checks"]:
        differs = row["transaction_origin_id"] != row["immediate_caller_id"]
        origin_gate = row["authorization_source"] == "transaction_origin"
        disposition = (
            "unknown"
            if not row["context_complete"]
            else "candidate_declared_origin_authorization_boundary"
            if origin_gate and differs and row["declared_authorized"]
            else "no_declared_origin_authorization_boundary"
        )
        projections.append(
            {
                "check_id": row["check_id"],
                "contract_id": row["contract_id"],
                "origin_differs_from_caller": differs,
                "authorization_source": row["authorization_source"],
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
        "check_count": len(model["checks"]),
        "check_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "solidity_parsed": False,
        "evm_executed": False,
        "chain_queried": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Principal identities, code decisions and authorization outcomes are caller-supplied.",
            "No Solidity source, bytecode, call graph or EVM trace is inspected.",
            "An origin-based label does not prove exploitable phishing or access control failure.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="EOA-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class EvmOriginAuthorizationReport:
    """Unsigned authorization projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise EvmOriginAuthorizationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> EvmOriginAuthorizationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_evm_origin_authorization(model: Any) -> EvmOriginAuthorizationReport:
    return EvmOriginAuthorizationReport._owned(_derive(model))


def verify_supplied_evm_origin_authorization(
    report: Any, *, model: Any
) -> EvmOriginAuthorizationReport:
    if type(report) is not EvmOriginAuthorizationReport:
        raise EvmOriginAuthorizationError("Exact EVM-origin wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise EvmOriginAuthorizationError("Report differs from separate original model")
    return EvmOriginAuthorizationReport._owned(expected)


def verify_supplied_evm_origin_authorization_bytes(
    report_bytes: bytes, *, model: Any
) -> EvmOriginAuthorizationReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise EvmOriginAuthorizationError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise EvmOriginAuthorizationError("Exported report differs from original replay")
    return EvmOriginAuthorizationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-evm-authorization",
        "checks": [
            {
                "check_id": "origin-check",
                "contract_id": "vault-one",
                "transaction_origin_id": "user-one",
                "immediate_caller_id": "proxy-one",
                "authorization_source": "transaction_origin",
                "declared_authorized": True,
                "context_complete": True,
            },
            {
                "check_id": "caller-check",
                "contract_id": "vault-one",
                "transaction_origin_id": "user-one",
                "immediate_caller_id": "proxy-one",
                "authorization_source": "immediate_caller",
                "declared_authorized": True,
                "context_complete": True,
            },
        ],
    }
