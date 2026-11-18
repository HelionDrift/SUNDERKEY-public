"""Compare a supplied synthetic SHAKEN PASSporT with claimed SIP numbers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from . import offline_framework_declaration_core as core
from .validation import loads_json_without_duplicate_keys

COMPONENT_ID = "social_supplied_passport_claim_review"
PROFILE_ID = "AOE-GA-D02-S02"
CAPABILITY_ID = "army.ga.d02.s02"
VECTOR_ID = "AV-GA-D02-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D02-S02"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GA-D02-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:f8ead040cee3ea48096bd6baf7283c048a04e2087c9aa800d6997e708447c9e0"
DOMAIN = "sunderkey.offline-passport-claim-review.v1"
MAX_MODEL_BYTES = 16_384
MAX_REPORT_BYTES = 32_768
B64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
TN = re.compile(r"[1-9][0-9]{7,14}\Z")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class PassportClaimReviewError(ValueError):
    """A synthetic PASSporT record or original-model replay is invalid."""


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _decode(segment: str, label: str, maximum: int) -> bytes:
    if not segment or len(segment) > maximum * 2 or B64URL.fullmatch(segment) is None:
        raise PassportClaimReviewError(f"Bounded {label} base64url segment required")
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, binascii.Error) as exc:
        raise PassportClaimReviewError(f"Invalid {label} base64url segment") from exc
    if len(raw) > maximum or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != segment:
        raise PassportClaimReviewError(f"Noncanonical {label} base64url segment")
    return raw


def _tn(value: Any, label: str) -> str:
    if type(value) is not str or TN.fullmatch(value) is None:
        raise PassportClaimReviewError(f"Bounded {label} telephone number required")
    return value


def _claims(segment: str, label: str) -> dict:
    raw = _decode(segment, label, 2_048)
    try:
        value = loads_json_without_duplicate_keys(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise PassportClaimReviewError(f"Invalid {label} JSON") from exc
    if type(value) is not dict:
        raise PassportClaimReviewError(f"Object {label} required")
    return value


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "synthetic_fixture", "sip_from_tn",
         "sip_to_tn", "passport_jws"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PassportClaimReviewError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise PassportClaimReviewError("Only synthetic fixtures are accepted")
    signaling_from = _tn(model["sip_from_tn"], "SIP From")
    signaling_to = _tn(model["sip_to_tn"], "SIP To")
    token = model["passport_jws"]
    if type(token) is not str or len(token) > 8_192:
        raise PassportClaimReviewError("Bounded JWS token required")
    parts = token.split(".")
    if len(parts) != 3:
        raise PassportClaimReviewError("Full-form JWS token required")
    header = core.exact(_claims(parts[0], "protected header"),
                        {"alg", "typ", "ppt", "x5u"}, "protected header")
    if header["alg"] != "ES256" or header["typ"] != "passport" or header["ppt"] != "shaken":
        raise PassportClaimReviewError("Closed SHAKEN header subset required")
    certificate_url = header["x5u"]
    if type(certificate_url) is not str or len(certificate_url) > 512:
        raise PassportClaimReviewError("Bounded certificate URL required")
    try:
        parsed_url = urlsplit(certificate_url)
    except ValueError as exc:
        raise PassportClaimReviewError("Invalid certificate URL") from exc
    if (parsed_url.scheme != "https" or not parsed_url.hostname
            or parsed_url.username or parsed_url.password):
        raise PassportClaimReviewError("HTTPS certificate URL required")
    claims = core.exact(_claims(parts[1], "payload"),
                        {"attest", "dest", "iat", "orig", "origid"}, "payload")
    if claims["attest"] not in ("A", "B", "C"):
        raise PassportClaimReviewError("SHAKEN attestation value required")
    origin = _tn(core.exact(claims["orig"], {"tn"}, "origin")["tn"], "origin")
    destination_list = core.exact(claims["dest"], {"tn"}, "destination")["tn"]
    if type(destination_list) is not list or len(destination_list) != 1:
        raise PassportClaimReviewError("One destination telephone number required")
    destination = _tn(destination_list[0], "destination")
    if type(claims["iat"]) is not int or claims["iat"] <= 0:
        raise PassportClaimReviewError("Positive integer issued-at required")
    origid = claims["origid"]
    if type(origid) is not str or UUID.fullmatch(origid) is None:
        raise PassportClaimReviewError("Origin UUID required")
    signature_bytes = _decode(parts[2], "signature", 128)
    if len(signature_bytes) != 64:
        raise PassportClaimReviewError("ES256 signature byte length required")
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "token_sha256": _digest(token),
        "certificate_url_sha256": _digest(certificate_url),
        "origid_sha256": _digest(origid),
        "declared_attestation": claims["attest"],
        "origin_matches_supplied_signaling": origin == signaling_from,
        "destination_matches_supplied_signaling": destination == signaling_to,
        "candidate_count": 0,
        "uncertainty": [
            "sip_signaling_and_token_origin_unauthenticated",
            "signature_certificate_chain_and_number_authority_unverified",
            "call_content_and_voice_authenticity_unobserved",
        ],
        "unknown_count": 3,
        "disposition": "unknown",
        "signature_verified": False,
        "caller_identity_verified": False,
        "deepfake_assessed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "A full-form synthetic SHAKEN JWS subset is decoded without "
            "cryptographic verification.",
            "Declared attestation and matching claims do not authenticate a caller or call.",
            "No certificate URL is dereferenced and no audio or call content is analyzed.",
            "No SIP request is sent or received and no voice pretext is produced.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PCR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class PassportClaimReviewReport:
    """Unsigned claim comparison requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise PassportClaimReviewError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> PassportClaimReviewReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_passport_claim(model: Any) -> PassportClaimReviewReport:
    return PassportClaimReviewReport._owned(_derive(model))


def verify_supplied_passport_claim(
    report: Any, *, model: Any
) -> PassportClaimReviewReport:
    if type(report) is not PassportClaimReviewReport:
        raise PassportClaimReviewError("Exact PASSporT wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise PassportClaimReviewError("Report differs from separate original model")
    return PassportClaimReviewReport._owned(expected)


def component_fixture() -> dict:
    header = {
        "alg": "ES256", "typ": "passport", "ppt": "shaken",
        "x5u": "https://cert.example.test/passport.cer",
    }
    claims = {
        "attest": "A",
        "dest": {"tn": ["12125550101"]},
        "iat": 1767225600,
        "orig": {"tn": "12125550100"},
        "origid": "123e4567-e89b-12d3-a456-426655440000",
    }
    segments = [
        base64.urlsafe_b64encode(
            json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        for item in (header, claims)
    ]
    segments.append(base64.urlsafe_b64encode(bytes(range(64))).rstrip(b"=").decode())
    return {
        "schema_version": 1,
        "source_id": "synthetic-passport-claim",
        "synthetic_fixture": True,
        "sip_from_tn": "12125550100",
        "sip_to_tn": "12125550101",
        "passport_jws": ".".join(segments),
    }
