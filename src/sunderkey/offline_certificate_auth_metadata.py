"""Project negative certificate-auth metadata invariants over synthetic records."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "identity_supplied_certificate_auth_metadata"
PROFILE_ID = "AOE-GA-D03-S07"
CAPABILITY_ID = "army.ga.d03.s07"
VECTOR_ID = "AV-GA-D03-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D03-S07"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GA-D03-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:70d73ee74db386b66004fbeb516193f7296660abbd1a5b0341a1738ad0113c55"
DOMAIN = "sunderkey.offline-certificate-auth-metadata.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_CERTIFICATES = 256
MAX_ISSUERS = 128
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


class CertificateAuthMetadataError(ValueError):
    """A supplied certificate model or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise CertificateAuthMetadataError(f"{label} must be a synthetic label")
    return identifier


def _tick(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_TICK:
        raise CertificateAuthMetadataError(f"{label} must be a bounded logical tick")
    return value


def _model(value: Any) -> tuple[dict, dict[str, dict], set[str]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "policy_complete", "certificates_complete",
            "issuers_complete", "order_complete", "trusted_issuers", "certificates",
            "observations",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CertificateAuthMetadataError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    for field in (
        "policy_complete", "certificates_complete", "issuers_complete", "order_complete",
    ):
        core.boolean(model[field], field)
    issuers = [
        _synthetic(item, "trusted issuer ID")
        for item in core.bounded_list(model["trusted_issuers"], MAX_ISSUERS, "issuers")
    ]
    if len(issuers) != len(set(issuers)):
        raise CertificateAuthMetadataError("Duplicate trusted issuer")
    certificates: dict[str, dict] = {}
    for item in core.bounded_list(model["certificates"], MAX_CERTIFICATES, "certificates"):
        row = core.exact(
            item,
            {
                "certificate_id", "issuer_id", "subject_id", "not_before", "not_after",
                "revoked_at", "client_auth_declared",
            },
            "certificate metadata",
        )
        certificate_id = _synthetic(row["certificate_id"], "certificate ID")
        if certificate_id in certificates:
            raise CertificateAuthMetadataError("Duplicate certificate ID")
        _synthetic(row["issuer_id"], "issuer ID")
        _synthetic(row["subject_id"], "subject ID")
        start = _tick(row["not_before"], "validity start")
        if start >= _tick(row["not_after"], "validity end"):
            raise CertificateAuthMetadataError("Certificate validity window is empty")
        if row["revoked_at"] is not None:
            revoked = _tick(row["revoked_at"], "revocation tick")
            if revoked < start:
                raise CertificateAuthMetadataError("Revocation precedes validity start")
        core.boolean(row["client_auth_declared"], "client auth usage")
        certificates[certificate_id] = row
    observations = core.bounded_list(model["observations"], MAX_OBSERVATIONS, "observations")
    if not observations:
        raise CertificateAuthMetadataError("At least one observation is required")
    seen: set[str] = set()
    for item in observations:
        row = core.exact(
            item,
            {
                "observation_id", "certificate_id", "expected_subject_id", "at_tick",
                "reported_outcome",
            },
            "observation",
        )
        observation_id = _synthetic(row["observation_id"], "observation ID")
        if observation_id in seen:
            raise CertificateAuthMetadataError("Duplicate observation ID")
        seen.add(observation_id)
        _synthetic(row["certificate_id"], "observation certificate ID")
        _synthetic(row["expected_subject_id"], "expected subject ID")
        _tick(row["at_tick"], "observation tick")
        core.choice(row["reported_outcome"], {"accepted", "rejected", "unknown"}, "outcome")
    return model, certificates, set(issuers)


def _project(observation: dict, model: dict, certificates: dict, issuers: set) -> dict:
    certificate = certificates.get(observation["certificate_id"])
    tick = observation["at_tick"]
    if not model["policy_complete"] or not model["order_complete"]:
        decision, basis = "unknown", "incomplete_policy_or_order"
    elif certificate is None:
        if model["certificates_complete"]:
            decision, basis = "deny", "certificate_absent_from_complete_inventory"
        else:
            decision, basis = "unknown", "certificate_inventory_incomplete"
    elif certificate["subject_id"] != observation["expected_subject_id"]:
        decision, basis = "deny", "declared_subject_mismatch"
    elif not certificate["client_auth_declared"]:
        decision, basis = "deny", "client_auth_usage_absent"
    elif tick < certificate["not_before"] or tick >= certificate["not_after"]:
        decision, basis = "deny", "outside_declared_validity"
    elif certificate["revoked_at"] is not None and tick >= certificate["revoked_at"]:
        decision, basis = "deny", "after_declared_revocation"
    elif certificate["issuer_id"] not in issuers and model["issuers_complete"]:
        decision, basis = "deny", "issuer_absent_from_complete_trust_set"
    elif certificate["issuer_id"] not in issuers:
        decision, basis = "unknown", "issuer_trust_set_incomplete"
    else:
        decision, basis = "unknown", "no_signature_or_chain_validation"
    reported = observation["reported_outcome"]
    if decision == "unknown" or reported == "unknown":
        assessment = "unknown"
    elif reported == "accepted":
        assessment = "candidate_declared_certificate_auth_conflict"
    else:
        assessment = "declared_rejection_consistent"
    return {
        "observation_id": observation["observation_id"],
        "certificate_id": observation["certificate_id"],
        "expected_subject_id": observation["expected_subject_id"],
        "at_tick": tick,
        "reported_outcome": reported,
        "projected_decision": decision,
        "basis": basis,
        "assessment": assessment,
    }


def _derive(value: Any) -> dict:
    model, certificates, issuers = _model(value)
    projections = [
        _project(item, model, certificates, issuers) for item in model["observations"]
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
                row["assessment"] == "candidate_declared_certificate_auth_conflict"
                for row in projections
            ),
            "unknown_count": sum(row["assessment"] == "unknown" for row in projections),
        },
        "source_authenticated": False,
        "certificate_metadata_authenticated": False,
        "issuer_trust_authenticated": False,
        "reported_outcomes_authenticated": False,
        "signature_or_chain_validated": False,
        "revocation_service_contacted": False,
        "effective_certificate_access_observed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Certificate metadata, trust labels, ordering and outcomes are declarations.",
            "Synthetic labels are not certificates, public keys, issuer names or SAN values.",
            "Direct issuer membership is not PKIX path or revocation-status validation.",
            "A candidate mismatch is not effective authentication or a vulnerability.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CAM-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class CertificateAuthMetadataReport:
    """Unsigned result wrapper requiring separately retained original input."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise CertificateAuthMetadataError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> CertificateAuthMetadataReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_certificate_auth_metadata(model: Any) -> CertificateAuthMetadataReport:
    try:
        return CertificateAuthMetadataReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise CertificateAuthMetadataError(str(exc)) from exc


def verify_supplied_certificate_auth_metadata(
    report: Any, *, model: Any,
) -> CertificateAuthMetadataReport:
    if type(report) is not CertificateAuthMetadataReport:
        raise CertificateAuthMetadataError("Exact report wrapper required")
    expected = analyze_supplied_certificate_auth_metadata(model)
    if report.to_json() != expected.to_json():
        raise CertificateAuthMetadataError("Report differs from separate original model")
    return expected


def verify_supplied_certificate_auth_metadata_bytes(
    report_bytes: bytes, *, model: Any,
) -> CertificateAuthMetadataReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise CertificateAuthMetadataError(str(exc)) from exc
    expected = analyze_supplied_certificate_auth_metadata(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise CertificateAuthMetadataError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:certificate-auth",
        "policy_complete": True,
        "certificates_complete": True,
        "issuers_complete": True,
        "order_complete": True,
        "trusted_issuers": ["synthetic:issuer-one"],
        "certificates": [
            {
                "certificate_id": "synthetic:certificate-one",
                "issuer_id": "synthetic:issuer-one",
                "subject_id": "synthetic:service-one",
                "not_before": 10,
                "not_after": 50,
                "revoked_at": 40,
                "client_auth_declared": True,
            },
        ],
        "observations": [
            {
                "observation_id": "synthetic:before-revocation",
                "certificate_id": "synthetic:certificate-one",
                "expected_subject_id": "synthetic:service-one",
                "at_tick": 20,
                "reported_outcome": "accepted",
            },
            {
                "observation_id": "synthetic:after-revocation",
                "certificate_id": "synthetic:certificate-one",
                "expected_subject_id": "synthetic:service-one",
                "at_tick": 45,
                "reported_outcome": "accepted",
            },
        ],
    }


__all__ = [
    "CertificateAuthMetadataError", "CertificateAuthMetadataReport",
    "analyze_supplied_certificate_auth_metadata",
    "verify_supplied_certificate_auth_metadata",
    "verify_supplied_certificate_auth_metadata_bytes", "component_fixture",
]
