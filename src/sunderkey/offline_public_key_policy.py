"""Parse supplied RSA and EC public SPKI bytes against a supplied policy."""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from . import offline_framework_declaration_core as core

COMPONENT_ID = "crypto_supplied_public_key_policy"
PROFILE_ID = "AOE-GE-D22-S06"
CAPABILITY_ID = "army.ge.d22.s06"
VECTOR_ID = "AV-GE-D22-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D22-S06"
WAVE_ID = "IW2-019"
COMMANDER_ID = "AOE-GE-D22-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:bb5660369a1c46e364b6b1978e841537475798934ec2b2cef42a4c470e53bf43"
DOMAIN = "sunderkey.offline-public-key-policy.v1"
MAX_MODEL_BYTES = 262_144
MAX_REPORT_BYTES = 131_072
MAX_DER_BYTES = 8192
MAX_KEYS = 16
MAX_CURVES = 16
B64 = re.compile(r"[A-Za-z0-9+/]{1,10924}={0,2}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class PublicKeyPolicyError(ValueError):
    """The public-key model or original-model replay is invalid."""


def _spki(value: Any) -> tuple[bytes, rsa.RSAPublicKey | ec.EllipticCurvePublicKey]:
    if type(value) is not str or B64.fullmatch(value) is None:
        raise PublicKeyPolicyError("Public SPKI must be bounded canonical base64")
    try:
        der = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PublicKeyPolicyError("Public SPKI base64 is invalid") from exc
    if not der or len(der) > MAX_DER_BYTES or base64.b64encode(der).decode("ascii") != value:
        raise PublicKeyPolicyError("Public SPKI base64 is not canonical or bounded")
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise PublicKeyPolicyError("Public SPKI DER is unsupported") from exc
    if not isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise PublicKeyPolicyError("Only RSA and EC public keys are accepted")
    if key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) != der:
        raise PublicKeyPolicyError("Exact canonical public SPKI is required")
    return der, key


def _model(value: Any) -> tuple[dict, str]:
    model = core.exact(
        value, {"schema_version", "source_id", "inventory_complete", "policy", "keys"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PublicKeyPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    policy = core.exact(
        model["policy"],
        {"min_rsa_bits", "allowed_rsa_exponents", "allowed_ec_curves"},
        "policy",
    )
    minimum = policy["min_rsa_bits"]
    if type(minimum) is not int or not 512 <= minimum <= 16384:
        raise PublicKeyPolicyError("Supplied minimum RSA bits are invalid")
    exponents = core.bounded_list(policy["allowed_rsa_exponents"], 8, "exponents")
    if not exponents or any(
        type(item) is not int or not 3 <= item <= 2**32 - 1
        for item in exponents
    ):
        raise PublicKeyPolicyError("Supplied RSA exponent policy is invalid")
    if len(exponents) != len(set(exponents)):
        raise PublicKeyPolicyError("Duplicate RSA exponent policy entry")
    curves = core.bounded_list(policy["allowed_ec_curves"], MAX_CURVES, "curves")
    if not curves:
        raise PublicKeyPolicyError("At least one EC curve must be declared")
    for curve in curves:
        core.identifier(curve, "EC curve")
    if len(curves) != len(set(curves)):
        raise PublicKeyPolicyError("Duplicate EC curve policy entry")
    seen: set[str] = set()
    for item in core.bounded_list(model["keys"], MAX_KEYS, "keys"):
        row = core.exact(item, {"key_id", "spki_der_b64", "policy_assertions_complete"}, "key")
        key_id = core.identifier(row["key_id"], "key ID")
        if key_id in seen:
            raise PublicKeyPolicyError("Duplicate key ID")
        seen.add(key_id)
        core.boolean(row["policy_assertions_complete"], "policy completeness")
        _spki(row["spki_der_b64"])
    try:
        text = core.canonical(model)
        if len(text.encode("ascii")) > MAX_MODEL_BYTES:
            raise PublicKeyPolicyError("Public-key model byte bound exceeded")
    except (TypeError, ValueError, RecursionError) as exc:
        if isinstance(exc, PublicKeyPolicyError):
            raise
        raise PublicKeyPolicyError("Public-key model cannot be canonicalized") from exc
    return json.loads(text), text


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    policy = model["policy"]
    keys: list[dict] = []
    signals: list[dict[str, str]] = []
    uncertainty: list[dict[str, str]] = []
    for row in sorted(model["keys"], key=lambda item: item["key_id"]):
        der, key = _spki(row["spki_der_b64"])
        key_id = row["key_id"]
        if isinstance(key, rsa.RSAPublicKey):
            family = "rsa"
            properties = {
                "modulus_bits": key.key_size,
                "public_exponent": key.public_numbers().e,
                "curve_name": None,
            }
            if row["policy_assertions_complete"]:
                if key.key_size < policy["min_rsa_bits"]:
                    signals.append({"key_id": key_id, "issue": "below_supplied_rsa_minimum"})
                if key.public_numbers().e not in policy["allowed_rsa_exponents"]:
                    signals.append({"key_id": key_id, "issue": "outside_supplied_rsa_exponents"})
        else:
            family = "ec"
            properties = {
                "modulus_bits": None,
                "public_exponent": None,
                "curve_name": key.curve.name,
            }
            if (
                row["policy_assertions_complete"]
                and key.curve.name not in policy["allowed_ec_curves"]
            ):
                signals.append({"key_id": key_id, "issue": "outside_supplied_ec_curves"})
        if not row["policy_assertions_complete"]:
            uncertainty.append({"key_id": key_id, "issue": "incomplete_declared_policy"})
        keys.append({
            "key_id": key_id,
            "spki_sha256": core.digest(der),
            "family": family,
            **properties,
        })
    if not model["inventory_complete"]:
        uncertainty.append({"key_id": "none", "issue": "incomplete_supplied_inventory"})
    signals.sort(key=lambda item: (item["key_id"], item["issue"]))
    uncertainty.sort(key=lambda item: (item["key_id"], item["issue"]))
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
        "inventory_complete_asserted": model["inventory_complete"],
        "key_count": len(keys),
        "keys": keys,
        "signals": signals,
        "uncertainty": uncertainty,
        "candidate_count": len(signals),
        "unknown_count": len(uncertainty) + int(not keys),
        "disposition": (
            "candidate_supplied_public_key_policy_review" if signals else
            "unknown" if uncertainty or not keys else
            "no_supplied_public_key_policy_difference"
        ),
        "source_authenticated": False,
        "private_key_loaded": False,
        "signature_verified": False,
        "key_use_verified": False,
        "policy_effectiveness_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "The policy and key inventory are supplied and unauthenticated.",
            "Only public RSA or EC SubjectPublicKeyInfo bytes are parsed.",
            "No signature, key use, provider state or effective policy is verified.",
            "A mismatch is a review question, not a standards or exploit verdict.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PKP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class PublicKeyPolicyReport:
    """Unsigned public-key projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise PublicKeyPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> PublicKeyPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_public_key_policy(model: Any) -> PublicKeyPolicyReport:
    return PublicKeyPolicyReport._owned(_derive(model))


def verify_supplied_public_key_policy(report: Any, *, model: Any) -> PublicKeyPolicyReport:
    if type(report) is not PublicKeyPolicyReport:
        raise PublicKeyPolicyError("Exact public-key wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise PublicKeyPolicyError("Report differs from separate original model")
    return PublicKeyPolicyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-public-spki",
        "inventory_complete": True,
        "policy": {
            "min_rsa_bits": 2048,
            "allowed_rsa_exponents": [65537],
            "allowed_ec_curves": ["secp384r1"],
        },
        "keys": [{
            "key_id": "toy_ec_public",
            "spki_der_b64": (
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncD"
                "fYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q=="
            ),
            "policy_assertions_complete": True,
        }],
    }
