"""Check supplied SPIFFE ID syntax and declared trust-domain membership offline."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "identity_supplied_spiffe_id_trust_projection"
PROFILE_ID = "AOE-GA-D03-S10"
CAPABILITY_ID = "army.ga.d03.s10"
VECTOR_ID = "AV-GA-D03-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D03-S10"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GA-D03-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:40d1935ce3c0677c2828ae6506a56822a7b1f99fb5e3b10e1f9afe79c93d394c"
DOMAIN = "sunderkey.offline-spiffe-id-trust-projection.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_DOMAINS = 128
MAX_OBSERVATIONS = 512
MAX_ID_BYTES = core.MAX_TEXT_BYTES
SOURCE_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
TRUST_DOMAIN = re.compile(r"[a-z0-9._-]{1,255}\Z")
SPIFFE_ID = re.compile(
    r"(?i:spiffe)://(?P<domain>[a-z0-9._-]{1,255})"
    r"(?P<path>(?:/[A-Za-z0-9._-]+)*)\Z"
)
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class SpiffeIdTrustProjectionError(ValueError):
    """A supplied SPIFFE model or separately sourced replay is invalid."""


def _source_id(value: Any) -> str:
    identifier = core.identifier(value, "source ID")
    if SOURCE_ID.fullmatch(identifier) is None:
        raise SpiffeIdTrustProjectionError("Source ID must be a synthetic label")
    return identifier


def _domain(value: Any) -> str:
    if type(value) is not str or TRUST_DOMAIN.fullmatch(value) is None:
        raise SpiffeIdTrustProjectionError("Trust domain declaration is invalid")
    return value


def _parse_spiffe_id(value: str) -> tuple[str | None, str]:
    if not value.isascii() or len(value.encode("ascii")) > MAX_ID_BYTES:
        return None, "invalid_spiffe_id"
    match = SPIFFE_ID.fullmatch(value)
    if match is None:
        return None, "invalid_spiffe_id"
    if any(segment in {".", ".."} for segment in match.group("path").split("/")):
        return None, "invalid_spiffe_id"
    return match.group("domain"), "well_formed_spiffe_id"


def _model(value: Any) -> tuple[dict, set[str]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "trust_policy_complete", "trusted_domains",
            "observations",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SpiffeIdTrustProjectionError("Unsupported model version")
    _source_id(model["source_id"])
    core.boolean(model["trust_policy_complete"], "trust policy completeness")
    domains = [
        _domain(item)
        for item in core.bounded_list(model["trusted_domains"], MAX_DOMAINS, "domains")
    ]
    if len(domains) != len(set(domains)):
        raise SpiffeIdTrustProjectionError("Duplicate trust domain")
    observations = core.bounded_list(model["observations"], MAX_OBSERVATIONS, "observations")
    if not observations:
        raise SpiffeIdTrustProjectionError("At least one observation is required")
    seen: set[str] = set()
    for item in observations:
        row = core.exact(
            item, {"observation_id", "spiffe_id", "reported_outcome"}, "observation"
        )
        observation_id = core.identifier(row["observation_id"], "observation ID")
        if SOURCE_ID.fullmatch(observation_id) is None or observation_id in seen:
            raise SpiffeIdTrustProjectionError("Observation ID is not unique and synthetic")
        seen.add(observation_id)
        if type(row["spiffe_id"]) is not str or not row["spiffe_id"]:
            raise SpiffeIdTrustProjectionError("SPIFFE ID observation must be text")
        if len(row["spiffe_id"].encode("utf-8")) > MAX_ID_BYTES:
            raise SpiffeIdTrustProjectionError("SPIFFE ID observation exceeds the bound")
        core.choice(row["reported_outcome"], {"accepted", "rejected", "unknown"}, "outcome")
    return model, set(domains)


def _project(observation: dict, model: dict, domains: set[str]) -> dict:
    trust_domain, syntax = _parse_spiffe_id(observation["spiffe_id"])
    if trust_domain is None:
        decision, basis = "deny", "invalid_spiffe_id"
    elif not model["trust_policy_complete"]:
        decision, basis = "unknown", "incomplete_trust_policy"
    elif trust_domain not in domains:
        decision, basis = "deny", "untrusted_declared_domain"
    else:
        decision, basis = "unknown", "no_svid_or_bundle_validation"
    reported = observation["reported_outcome"]
    if decision == "unknown" or reported == "unknown":
        assessment = "unknown"
    elif reported == "accepted":
        assessment = "candidate_declared_trust_boundary_conflict"
    else:
        assessment = "declared_rejection_consistent"
    return {
        "observation_id": observation["observation_id"],
        "spiffe_id": observation["spiffe_id"],
        "parsed_trust_domain": trust_domain,
        "syntax": syntax,
        "reported_outcome": reported,
        "projected_decision": decision,
        "basis": basis,
        "assessment": assessment,
    }


def _derive(value: Any) -> dict:
    model, domains = _model(value)
    projections = [_project(item, model, domains) for item in model["observations"]]
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
                row["assessment"] == "candidate_declared_trust_boundary_conflict"
                for row in projections
            ),
            "unknown_count": sum(row["assessment"] == "unknown" for row in projections),
        },
        "source_authenticated": False,
        "trust_policy_authenticated": False,
        "reported_outcomes_authenticated": False,
        "svid_signature_validated": False,
        "trust_bundle_validated": False,
        "effective_workload_access_observed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "SPIFFE IDs, trust domains, policy completeness and outcomes are declarations.",
            "Syntax and domain membership do not establish cryptographic workload identity.",
            "A trusted domain remains unknown without SVID and bundle validation.",
            "A candidate mismatch is not observed access or a verified vulnerability.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SIP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class SpiffeIdTrustProjectionReport:
    """Unsigned result wrapper requiring separately retained original input."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SpiffeIdTrustProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SpiffeIdTrustProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_spiffe_id_trust(model: Any) -> SpiffeIdTrustProjectionReport:
    try:
        return SpiffeIdTrustProjectionReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise SpiffeIdTrustProjectionError(str(exc)) from exc


def verify_supplied_spiffe_id_trust(
    report: Any, *, model: Any,
) -> SpiffeIdTrustProjectionReport:
    if type(report) is not SpiffeIdTrustProjectionReport:
        raise SpiffeIdTrustProjectionError("Exact report wrapper required")
    expected = analyze_supplied_spiffe_id_trust(model)
    if report.to_json() != expected.to_json():
        raise SpiffeIdTrustProjectionError("Report differs from separate original model")
    return expected


def verify_supplied_spiffe_id_trust_bytes(
    report_bytes: bytes, *, model: Any,
) -> SpiffeIdTrustProjectionReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise SpiffeIdTrustProjectionError(str(exc)) from exc
    expected = analyze_supplied_spiffe_id_trust(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise SpiffeIdTrustProjectionError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:spiffe-trust",
        "trust_policy_complete": True,
        "trusted_domains": ["example.org"],
        "observations": [
            {
                "observation_id": "synthetic:trusted-id",
                "spiffe_id": "spiffe://example.org/service/reader",
                "reported_outcome": "accepted",
            },
            {
                "observation_id": "synthetic:untrusted-id",
                "spiffe_id": "spiffe://other.example/workload",
                "reported_outcome": "accepted",
            },
        ],
    }


__all__ = [
    "SpiffeIdTrustProjectionError", "SpiffeIdTrustProjectionReport",
    "analyze_supplied_spiffe_id_trust", "verify_supplied_spiffe_id_trust",
    "verify_supplied_spiffe_id_trust_bytes", "component_fixture",
]
