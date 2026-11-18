"""Locally sign API access assertions without claiming policy authority."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .offline_api_access_expectations import (
    OfflineApiAccessExpectationError,
    bind_offline_api_case_to_access_expectations,
    bind_offline_api_retest_to_access_expectations,
    verify_offline_api_access_expectations,
)
from .offline_api_assessment import OfflineApiCaseSource
from .reference_adapters import OfflineReferenceAdapter

ATTESTATION_DOMAIN = "sunderkey.offline-api-expectation-attestation.v1"
BINDING_DOMAIN = "sunderkey.offline-api-signed-expectation-binding.v1"
RETEST_BINDING_DOMAIN = "sunderkey.offline-api-signed-retest-expectation-binding.v1"
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
NO_EFFECTS = {
    "authorization": "none",
    "credential_resolution": "none",
    "execution": "none",
    "finding_publication": "none",
    "network": "none",
    "qualification": "none",
    "target_interaction": "none",
}


class OfflineApiExpectationAttestationError(ValueError):
    """Raised when the local signer or exact expectation binding differs."""


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or IDENTIFIER_RE.fullmatch(value) is None:
        raise OfflineApiExpectationAttestationError(f"{label} is invalid")
    return value


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise OfflineApiExpectationAttestationError("signed expectation is not JSON data") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _expectations(value: Mapping[str, Any]) -> dict[str, Any]:
    if not _native_keys(value) or any(
        type(value.get(field)) is not str
        for field in (
            "expectation_id",
            "mission_id",
            "target_id",
            "scope_id",
            "object_id",
            "action",
            "expectations_sha256",
        )
    ):
        raise OfflineApiExpectationAttestationError("access expectations do not replay")
    entries = value.get("principal_expectations")
    if not isinstance(entries, (list, tuple)) or any(
        not _native_keys(item) or type(item.get("principal_id")) is not str for item in entries
    ):
        raise OfflineApiExpectationAttestationError("access expectations do not replay")
    try:
        return verify_offline_api_access_expectations(value)
    except OfflineApiAccessExpectationError as exc:
        raise OfflineApiExpectationAttestationError("access expectations do not replay") from exc


@dataclass(frozen=True, slots=True)
class OfflineAccessPolicyKeyBinding:
    policy_owner_id: str
    key_id: str
    public_key: Ed25519PublicKey

    def __post_init__(self) -> None:
        _binding(self)


def _native_keys(value: Any) -> bool:
    return isinstance(value, Mapping) and all(type(key) is str for key in value)


def _binding(value: Any) -> tuple[str, str, Ed25519PublicKey]:
    if type(value) is not OfflineAccessPolicyKeyBinding:
        raise OfflineApiExpectationAttestationError("policy key binding is invalid")
    owner_id, key_id, public_key = value.policy_owner_id, value.key_id, value.public_key
    _identifier(owner_id, "policy_owner_id")
    _identifier(key_id, "key_id")
    if not isinstance(public_key, Ed25519PublicKey):
        raise OfflineApiExpectationAttestationError("Ed25519 public key is required")
    return owner_id, key_id, public_key


def _body(
    *,
    expectations: Mapping[str, Any],
    policy_owner_id: str,
    key_id: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "expectations_sha256": expectations["expectations_sha256"],
        "mission_id": expectations["mission_id"],
        "target_id": expectations["target_id"],
        "scope_id": expectations["scope_id"],
        "object_id": expectations["object_id"],
        "action": expectations["action"],
        "policy_owner_id": policy_owner_id,
        "key_id": key_id,
        "identity_assurance": "caller_pinned_local_key_only",
        "policy_authority_verified": False,
        "pre_observation_commitment_verified": False,
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }


def sign_offline_api_access_expectations(
    *,
    expectations: Mapping[str, Any],
    policy_owner_id: str,
    key_id: str,
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Sign a reproduced assertion set with a caller-held local key."""

    checked = _expectations(expectations)
    _identifier(policy_owner_id, "policy_owner_id")
    _identifier(key_id, "key_id")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise OfflineApiExpectationAttestationError("Ed25519 private key is required")
    body = _body(expectations=checked, policy_owner_id=policy_owner_id, key_id=key_id)
    signature = private_key.sign(_canonical({"domain": ATTESTATION_DOMAIN, "body": body}))
    signed = {**body, "signature_base64": base64.b64encode(signature).decode("ascii")}
    return {
        **signed,
        "attestation_sha256": _digest({"domain": ATTESTATION_DOMAIN, "signed": signed}),
    }


def verify_offline_api_access_expectation_attestation(
    *,
    expectations: Mapping[str, Any],
    document: Mapping[str, Any],
    binding: OfflineAccessPolicyKeyBinding,
) -> dict[str, Any]:
    """Verify immutable local signature, not policy-owner authority or timing."""

    checked = _expectations(expectations)
    owner_id, key_id, public_key = _binding(binding)
    if not _native_keys(document):
        raise OfflineApiExpectationAttestationError("attestation inputs are invalid")
    expected = _body(
        expectations=checked,
        policy_owner_id=owner_id,
        key_id=key_id,
    )
    if set(document) != set(expected) | {"signature_base64", "attestation_sha256"}:
        raise OfflineApiExpectationAttestationError("attestation context differs")
    if any(
        type(document[field]) is not str for field, item in expected.items() if type(item) is str
    ):
        raise OfflineApiExpectationAttestationError("attestation context strings are invalid")
    if (
        type(document["effects"]) is not dict
        or not _native_keys(document["effects"])
        or set(document["effects"]) != set(NO_EFFECTS)
        or any(type(item) is not str for item in document["effects"].values())
    ):
        raise OfflineApiExpectationAttestationError("attestation context effects are invalid")
    if (
        _canonical({key: document[key] for key in expected}) != _canonical(expected)
        or type(document["signature_base64"]) is not str
        or len(document["signature_base64"]) != 88
        or type(document["attestation_sha256"]) is not str
        or SHA_RE.fullmatch(document["attestation_sha256"]) is None
    ):
        raise OfflineApiExpectationAttestationError("attestation context differs")
    signed = {**expected, "signature_base64": document["signature_base64"]}
    if document["attestation_sha256"] != _digest({"domain": ATTESTATION_DOMAIN, "signed": signed}):
        raise OfflineApiExpectationAttestationError("attestation digest differs")
    try:
        signature = base64.b64decode(document["signature_base64"], validate=True)
        if len(signature) != 64:
            raise ValueError("signature length")
        public_key.verify(signature, _canonical({"domain": ATTESTATION_DOMAIN, "body": expected}))
    except (InvalidSignature, binascii.Error, ValueError, TypeError) as exc:
        raise OfflineApiExpectationAttestationError("signature verification failed") from exc
    return json.loads(_canonical({**signed, "attestation_sha256": document["attestation_sha256"]}))


def bind_offline_api_case_to_signed_access_expectations(
    *,
    adapter: OfflineReferenceAdapter,
    source: OfflineApiCaseSource,
    expectations: Mapping[str, Any],
    attestation: Mapping[str, Any],
    binding: OfflineAccessPolicyKeyBinding,
) -> dict[str, Any]:
    """Require both signature replay and exact synthetic case label binding."""

    verified = verify_offline_api_access_expectation_attestation(
        expectations=expectations, document=attestation, binding=binding
    )
    try:
        case_binding = bind_offline_api_case_to_access_expectations(
            adapter=adapter, source=source, expectations=expectations
        )
    except OfflineApiAccessExpectationError as exc:
        raise OfflineApiExpectationAttestationError("API case labels do not replay") from exc
    body = {
        "schema_version": 1,
        "expectations_sha256": verified["expectations_sha256"],
        "attestation_sha256": verified["attestation_sha256"],
        "case_binding_sha256": case_binding["binding_sha256"],
        "case_result_sha256": case_binding["case_result_sha256"],
        "identity_assurance": "caller_pinned_local_key_only",
        "policy_authority_verified": False,
        "pre_observation_commitment_verified": False,
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "binding_sha256": _digest({"domain": BINDING_DOMAIN, "body": body})}


def verify_offline_api_signed_access_expectation_binding(
    *,
    adapter: OfflineReferenceAdapter,
    source: OfflineApiCaseSource,
    expectations: Mapping[str, Any],
    attestation: Mapping[str, Any],
    binding: OfflineAccessPolicyKeyBinding,
    document: Mapping[str, Any],
) -> dict[str, Any]:
    expected = bind_offline_api_case_to_signed_access_expectations(
        adapter=adapter,
        source=source,
        expectations=expectations,
        attestation=attestation,
        binding=binding,
    )
    if not isinstance(document, Mapping) or _canonical(document) != _canonical(expected):
        raise OfflineApiExpectationAttestationError("signed case binding does not replay")
    return expected


def bind_offline_api_retest_to_signed_access_expectations(
    *,
    adapter: OfflineReferenceAdapter,
    prior_source: OfflineApiCaseSource,
    second_source: OfflineApiCaseSource,
    expectations: Mapping[str, Any],
    attestation: Mapping[str, Any],
    binding: OfflineAccessPolicyKeyBinding,
) -> dict[str, Any]:
    """Replay both cases against one locally signed assertion set."""

    verified = verify_offline_api_access_expectation_attestation(
        expectations=expectations, document=attestation, binding=binding
    )
    try:
        retest = bind_offline_api_retest_to_access_expectations(
            adapter=adapter,
            prior_source=prior_source,
            second_source=second_source,
            expectations=expectations,
        )
    except OfflineApiAccessExpectationError as exc:
        raise OfflineApiExpectationAttestationError("API retest labels do not replay") from exc
    body = {
        "schema_version": 1,
        "expectations_sha256": verified["expectations_sha256"],
        "attestation_sha256": verified["attestation_sha256"],
        "retest_binding_sha256": retest["binding_sha256"],
        "prior_binding_sha256": retest["prior_binding_sha256"],
        "second_binding_sha256": retest["second_binding_sha256"],
        "observation_change": retest["observation_change"],
        "identity_assurance": "caller_pinned_local_key_only",
        "policy_authority_verified": False,
        "pre_observation_commitment_verified": False,
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }
    return {
        **body,
        "binding_sha256": _digest({"domain": RETEST_BINDING_DOMAIN, "body": body}),
    }


def verify_offline_api_signed_retest_expectation_binding(
    *,
    adapter: OfflineReferenceAdapter,
    prior_source: OfflineApiCaseSource,
    second_source: OfflineApiCaseSource,
    expectations: Mapping[str, Any],
    attestation: Mapping[str, Any],
    binding: OfflineAccessPolicyKeyBinding,
    document: Mapping[str, Any],
) -> dict[str, Any]:
    expected = bind_offline_api_retest_to_signed_access_expectations(
        adapter=adapter,
        prior_source=prior_source,
        second_source=second_source,
        expectations=expectations,
        attestation=attestation,
        binding=binding,
    )
    if not isinstance(document, Mapping) or _canonical(document) != _canonical(expected):
        raise OfflineApiExpectationAttestationError("signed retest binding does not replay")
    return expected


__all__ = [
    "OfflineAccessPolicyKeyBinding",
    "OfflineApiExpectationAttestationError",
    "bind_offline_api_case_to_signed_access_expectations",
    "bind_offline_api_retest_to_signed_access_expectations",
    "sign_offline_api_access_expectations",
    "verify_offline_api_access_expectation_attestation",
    "verify_offline_api_signed_access_expectation_binding",
    "verify_offline_api_signed_retest_expectation_binding",
]
