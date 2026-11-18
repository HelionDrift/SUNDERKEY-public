"""Project supplied key and nonce label reuse without cryptographic material."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "crypto_supplied_symmetric_nonce_reuse"
PROFILE_ID = "AOE-GE-D22-S05"
CAPABILITY_ID = "army.ge.d22.s05"
VECTOR_ID = "AV-GE-D22-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D22-S05"
WAVE_ID = "IW2-018"
COMMANDER_ID = "AOE-GE-D22-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:ec14beb3b851ec961352e148489632d039dfe75bc6022d578eebab48dc87ffe5"
DOMAIN = "sunderkey.offline-symmetric-nonce-reuse.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_RECORDS = 512
SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
MODES = {"aes_gcm", "chacha20_poly1305", "aes_ctr"}
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class SymmetricNonceReuseError(ValueError):
    """A supplied nonce model or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise SymmetricNonceReuseError(f"{label} must be synthetic")
    return identifier


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "policy_complete", "records_complete",
            "order_complete", "unique_nonce_required", "records",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SymmetricNonceReuseError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    for field in (
        "policy_complete", "records_complete", "order_complete", "unique_nonce_required",
    ):
        core.boolean(model[field], field)
    records = core.bounded_list(model["records"], MAX_RECORDS, "records")
    if not records:
        raise SymmetricNonceReuseError("At least one record is required")
    seen: set[str] = set()
    for item in records:
        row = core.exact(
            item, {"record_id", "key_id", "nonce_id", "mode", "operation"}, "record"
        )
        record_id = _synthetic(row["record_id"], "record ID")
        if record_id in seen:
            raise SymmetricNonceReuseError("Duplicate record ID")
        seen.add(record_id)
        _synthetic(row["key_id"], "key ID")
        _synthetic(row["nonce_id"], "nonce ID")
        core.choice(row["mode"], MODES, "mode")
        core.choice(row["operation"], {"encrypt", "decrypt"}, "operation")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    complete = all(
        model[field] for field in ("policy_complete", "records_complete", "order_complete")
    )
    prior_encryption: dict[tuple[str, str, str], str] = {}
    projections: list[dict] = []
    for row in model["records"]:
        pair = (row["key_id"], row["mode"], row["nonce_id"])
        prior_id = prior_encryption.get(pair)
        reused = row["operation"] == "encrypt" and prior_id is not None
        if row["operation"] == "encrypt" and prior_id is None:
            prior_encryption[pair] = row["record_id"]
        disposition = (
            "unknown_incomplete_declarations" if not complete
            else "not_assessed_decryption" if row["operation"] == "decrypt"
            else "candidate_declared_nonce_reuse"
            if model["unique_nonce_required"] and reused
            else "no_declared_nonce_reuse_conflict"
        )
        projections.append({
            "record_id": row["record_id"],
            "key_id": row["key_id"],
            "mode": row["mode"],
            "nonce_id": row["nonce_id"],
            "operation": row["operation"],
            "prior_encryption_record_id": prior_id if reused else None,
            "disposition": disposition,
        })
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
            "record_count": len(projections),
            "candidate_count": sum(
                item["disposition"] == "candidate_declared_nonce_reuse"
                for item in projections
            ),
            "unknown_count": sum(
                item["disposition"] == "unknown_incomplete_declarations"
                for item in projections
            ),
        },
        "source_authenticated": False,
        "policy_authenticated": False,
        "key_identity_verified": False,
        "nonce_value_verified": False,
        "operation_observed": False,
        "key_or_ciphertext_processed": False,
        "encryption_performed": False,
        "cryptographic_break_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Mode, key, nonce, operation, policy and completeness are caller declarations.",
            "Matching synthetic labels do not prove identical key or nonce bytes.",
            "A declared reuse conflict does not prove confidentiality loss or exploitability.",
            "No key, nonce value, plaintext, ciphertext, service or target is processed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SNR-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class SymmetricNonceReuseReport:
    """Unsigned nonce-label projection requiring separate original replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SymmetricNonceReuseError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SymmetricNonceReuseReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_symmetric_nonce_reuse(model: Any) -> SymmetricNonceReuseReport:
    try:
        return SymmetricNonceReuseReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise SymmetricNonceReuseError(str(exc)) from exc


def verify_supplied_symmetric_nonce_reuse(
    report: Any, *, model: Any,
) -> SymmetricNonceReuseReport:
    if type(report) is not SymmetricNonceReuseReport:
        raise SymmetricNonceReuseError("Exact report wrapper required")
    expected = analyze_supplied_symmetric_nonce_reuse(model)
    if report.to_json() != expected.to_json():
        raise SymmetricNonceReuseError("Report differs from separate original model")
    return expected


def verify_supplied_symmetric_nonce_reuse_bytes(
    report_bytes: bytes, *, model: Any,
) -> SymmetricNonceReuseReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise SymmetricNonceReuseError(str(exc)) from exc
    expected = analyze_supplied_symmetric_nonce_reuse(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise SymmetricNonceReuseError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:nonce-records",
        "policy_complete": True,
        "records_complete": True,
        "order_complete": True,
        "unique_nonce_required": True,
        "records": [
            {"record_id": "synthetic:encrypt-one", "key_id": "synthetic:key-one",
             "nonce_id": "synthetic:nonce-one", "mode": "aes_gcm", "operation": "encrypt"},
            {"record_id": "synthetic:decrypt-one", "key_id": "synthetic:key-one",
             "nonce_id": "synthetic:nonce-one", "mode": "aes_gcm", "operation": "decrypt"},
            {"record_id": "synthetic:encrypt-two", "key_id": "synthetic:key-one",
             "nonce_id": "synthetic:nonce-one", "mode": "aes_gcm", "operation": "encrypt"},
        ],
    }


__all__ = [
    "SymmetricNonceReuseError", "SymmetricNonceReuseReport",
    "analyze_supplied_symmetric_nonce_reuse", "verify_supplied_symmetric_nonce_reuse",
    "verify_supplied_symmetric_nonce_reuse_bytes", "component_fixture",
]
