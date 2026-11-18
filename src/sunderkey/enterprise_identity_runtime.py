"""Fail-closed enterprise identity runtime boundaries.

The OIDC verifier operates entirely offline with an authenticated,
policy-bound pinned RSA keyset. The SCIM boundary accepts an authenticated
admission, an environment-attested injected dispatcher, and an injected atomic
idempotency store after the existing enterprise identity contracts have
admitted the command. This module contains no network client, credential
provider, discovery client, filesystem access, or production authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, ClassVar, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .enterprise_identity_contracts import (
    Decision,
    EnterpriseIdentityPolicy,
    IdentityDecision,
    ProvisioningCommand,
    ProvisioningOperation,
    RoleBinding,
    VerifiedSsoAssertion,
    admit_sso_assertion,
    canonical_json,
    canonical_sha256,
    validate_provisioning_command,
)

SCHEMA_VERSION = 1
RECEIPT_KIND = "sunderkey.enterprise-identity-runtime-receipt.v1"
ADMISSION_KIND = "sunderkey.provisioning-dispatch-admission.v1"
KEYSET_KIND = "sunderkey.authenticated-pinned-oidc-keyset.v1"
RESERVATION_KIND = "sunderkey.scim-idempotency-reservation.v1"
COMPLETION_KIND = "sunderkey.scim-idempotency-completion.v1"
ALLOWED_JWS_ALGORITHM = "RS256"
MAX_TOKEN_BYTES = 65_536
MAX_HEADER_BYTES = 4_096
MAX_CLAIMS_BYTES = 32_768
MAX_PINNED_KEYS = 32
MAX_REQUIRED_CLAIMS = 32

ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
CLAIM_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
RECEIPT_ID_RE = re.compile(r"EIR-[0-9A-F]{32}\Z")
ADMISSION_ID_RE = re.compile(r"EIA-[0-9A-F]{32}\Z")

NO_EFFECTS = {
    "authority": "none",
    "built_in_network": "none",
    "credential_values": "none",
    "production": "none",
    "qualification": "none",
    "raw_directory_payloads": "none",
}


class EnterpriseIdentityRuntimeError(ValueError):
    """Raised when an enterprise identity runtime boundary fails closed."""


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise EnterpriseIdentityRuntimeError(f"{label} must be a safe identifier")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        raise EnterpriseIdentityRuntimeError(f"{label} must be a SHA-256 content address")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise EnterpriseIdentityRuntimeError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise EnterpriseIdentityRuntimeError(f"{label} must be a valid timestamp") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _epoch(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EnterpriseIdentityRuntimeError(f"{label} must be an integer epoch second")
    if not 0 <= value <= 253_402_300_799:
        raise EnterpriseIdentityRuntimeError(f"{label} is outside the supported range")
    return value


def _epoch_timestamp(value: int, label: str) -> str:
    try:
        return datetime.fromtimestamp(value, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError) as exc:
        raise EnterpriseIdentityRuntimeError(f"{label} is outside the supported range") from exc


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _rsa_spki_sha256(public_key: rsa.RSAPublicKey) -> str:
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _b64url_decode(segment: str, label: str, maximum: int) -> bytes:
    if not segment or BASE64URL_RE.fullmatch(segment) is None:
        raise EnterpriseIdentityRuntimeError(f"{label} is not strict unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, binascii.Error) as exc:
        raise EnterpriseIdentityRuntimeError(f"{label} is not valid base64url") from exc
    if len(decoded) > maximum:
        raise EnterpriseIdentityRuntimeError(f"{label} exceeds the size limit")
    return decoded


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise EnterpriseIdentityRuntimeError(f"{label} contains a duplicate member")
            value[key] = item
        return value

    try:
        decoded = raw.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=reject_duplicate,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except EnterpriseIdentityRuntimeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise EnterpriseIdentityRuntimeError(f"{label} must be a strict JSON object") from exc
    if not isinstance(value, dict):
        raise EnterpriseIdentityRuntimeError(f"{label} must be a JSON object")
    return value


def _string_claim(claims: Mapping[str, Any], name: str) -> str:
    value = claims.get(name)
    return _identifier(value, f"OIDC {name} claim")


def _string_list_claim(claims: Mapping[str, Any], name: str) -> tuple[str, ...]:
    value = claims.get(name)
    if not isinstance(value, list) or not value or len(value) > 16:
        raise EnterpriseIdentityRuntimeError(f"OIDC {name} claim must be a bounded string list")
    normalized = tuple(_identifier(item, f"OIDC {name} item") for item in value)
    if len(normalized) != len(set(normalized)):
        raise EnterpriseIdentityRuntimeError(f"OIDC {name} claim must not contain duplicates")
    return normalized


def _validate_required_claims(
    claims: Mapping[str, Any], required_claims: Mapping[str, str]
) -> None:
    if not isinstance(required_claims, Mapping) or len(required_claims) > MAX_REQUIRED_CLAIMS:
        raise EnterpriseIdentityRuntimeError("required_claims must be a bounded mapping")
    reserved = {
        "acr",
        "amr",
        "aud",
        "auth_time",
        "exp",
        "iat",
        "iss",
        "jti",
        "nbf",
        "nonce",
        "sid",
        "sub",
        "tenant_id",
    }
    for name, expected in required_claims.items():
        if not isinstance(name, str) or CLAIM_NAME_RE.fullmatch(name) is None:
            raise EnterpriseIdentityRuntimeError("required claim name is invalid")
        if name in reserved:
            raise EnterpriseIdentityRuntimeError("reserved OIDC claims have dedicated checks")
        expected = _identifier(expected, f"required claim {name}")
        if claims.get(name) != expected:
            raise EnterpriseIdentityRuntimeError("a required OIDC claim did not match")


@dataclass(frozen=True)
class AuthenticatedPinnedOidcKeyset:
    """Authenticated offline keyset bound to one enterprise identity policy."""

    keyset_id: str
    policy_sha256: str
    issuer: str
    audience: str
    public_keys: Mapping[str, rsa.RSAPublicKey] = field(repr=False, compare=False)
    key_fingerprints_sha256: Mapping[str, str]
    authenticator_id: str
    authentication_sha256: str
    issued_at: str
    expires_at: str
    keyset_sha256: str = field(init=False)

    KIND: ClassVar[str] = KEYSET_KIND

    def __post_init__(self) -> None:
        object.__setattr__(self, "keyset_id", _identifier(self.keyset_id, "keyset_id"))
        object.__setattr__(
            self,
            "policy_sha256",
            _digest(self.policy_sha256, "keyset policy_sha256"),
        )
        object.__setattr__(self, "issuer", _identifier(self.issuer, "keyset issuer"))
        object.__setattr__(self, "audience", _identifier(self.audience, "keyset audience"))
        object.__setattr__(
            self,
            "authenticator_id",
            _identifier(self.authenticator_id, "keyset authenticator_id"),
        )
        object.__setattr__(
            self,
            "authentication_sha256",
            _digest(self.authentication_sha256, "keyset authentication_sha256"),
        )
        object.__setattr__(self, "issued_at", _timestamp(self.issued_at, "keyset issued_at"))
        object.__setattr__(self, "expires_at", _timestamp(self.expires_at, "keyset expires_at"))
        if _instant(self.expires_at) <= _instant(self.issued_at):
            raise EnterpriseIdentityRuntimeError("keyset validity interval is empty")
        if not isinstance(self.public_keys, Mapping) or not (
            1 <= len(self.public_keys) <= MAX_PINNED_KEYS
        ):
            raise EnterpriseIdentityRuntimeError("keyset public_keys must be a bounded mapping")
        if not isinstance(self.key_fingerprints_sha256, Mapping):
            raise EnterpriseIdentityRuntimeError("keyset fingerprints must be a mapping")
        normalized_keys: dict[str, rsa.RSAPublicKey] = {}
        normalized_fingerprints: dict[str, str] = {}
        for candidate_id, candidate_key in self.public_keys.items():
            normalized_id = _identifier(candidate_id, "pinned key ID")
            if not isinstance(candidate_key, rsa.RSAPublicKey):
                raise EnterpriseIdentityRuntimeError("pinned key must be an RSA public key")
            if not 2048 <= candidate_key.key_size <= 8192:
                raise EnterpriseIdentityRuntimeError("pinned RSA key size is rejected")
            declared = self.key_fingerprints_sha256.get(candidate_id)
            fingerprint = _digest(declared, "pinned key fingerprint")
            if fingerprint != _rsa_spki_sha256(candidate_key):
                raise EnterpriseIdentityRuntimeError("pinned key fingerprint does not match")
            normalized_keys[normalized_id] = candidate_key
            normalized_fingerprints[normalized_id] = fingerprint
        if set(normalized_fingerprints) != set(self.key_fingerprints_sha256):
            raise EnterpriseIdentityRuntimeError(
                "keyset key and fingerprint IDs must match exactly"
            )
        object.__setattr__(self, "public_keys", MappingProxyType(normalized_keys))
        object.__setattr__(
            self,
            "key_fingerprints_sha256",
            MappingProxyType(normalized_fingerprints),
        )
        object.__setattr__(self, "keyset_sha256", canonical_sha256(self._body()))

    def _body(self) -> dict[str, Any]:
        return {
            "audience": self.audience,
            "authentication_sha256": self.authentication_sha256,
            "authenticator_id": self.authenticator_id,
            "expires_at": self.expires_at,
            "issuer": self.issuer,
            "key_fingerprints_sha256": dict(sorted(self.key_fingerprints_sha256.items())),
            "keyset_id": self.keyset_id,
            "kind": self.KIND,
            "issued_at": self.issued_at,
            "policy_sha256": self.policy_sha256,
            "schema_version": SCHEMA_VERSION,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "keyset_sha256": self.keyset_sha256}


class AuthenticatedOidcKeysetVerifier(Protocol):
    """Injected verifier for a signed or otherwise authenticated keyset."""

    verifier_id: str

    def verify(self, keyset: AuthenticatedPinnedOidcKeyset) -> bool:
        """Return true only after authenticating the exact keyset content."""


@dataclass(frozen=True)
class EnterpriseIdentityRuntimeReceipt:
    """Content-addressed, secret-free record of one admitted runtime operation."""

    operation: str
    status: str
    tenant_id: str
    subject_id: str
    evaluated_at: str
    policy_sha256: str
    source_sha256: str
    evidence_sha256: str
    decision_sha256: str
    dispatch_count: int
    algorithm: str | None = None
    key_id: str | None = None
    key_fingerprint_sha256: str | None = None
    keyset_id: str | None = None
    keyset_sha256: str | None = None
    assurance_context: str | None = None
    replay_binding_sha256: str | None = None
    idempotency_key: str | None = None
    admission_id: str | None = None
    admission_sha256: str | None = None
    admission_authenticator_id: str | None = None
    admission_authentication_sha256: str | None = None
    environment: str | None = None
    dispatcher_id: str | None = None
    dispatcher_attestation_sha256: str | None = None
    idempotency_store_id: str | None = None
    reservation_id: str | None = None
    reservation_sha256: str | None = None
    completion_id: str | None = None
    completion_sha256: str | None = None
    receipt_id: str = field(init=False)
    receipt_sha256: str = field(init=False)

    KIND: ClassVar[str] = RECEIPT_KIND

    def __post_init__(self) -> None:
        if self.operation not in {"oidc_jws_verification", "scim_dispatch"}:
            raise EnterpriseIdentityRuntimeError("receipt operation is invalid")
        expected_status = {
            "oidc_jws_verification": "verified_and_admitted",
            "scim_dispatch": "dispatched_non_production",
        }[self.operation]
        if self.status != expected_status:
            raise EnterpriseIdentityRuntimeError("receipt status is invalid")
        for name in ("tenant_id", "subject_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), f"receipt {name}"))
        object.__setattr__(self, "evaluated_at", _timestamp(self.evaluated_at, "evaluated_at"))
        for name in ("policy_sha256", "source_sha256", "evidence_sha256", "decision_sha256"):
            object.__setattr__(self, name, _digest(getattr(self, name), f"receipt {name}"))
        if self.dispatch_count not in {0, 1}:
            raise EnterpriseIdentityRuntimeError("dispatch_count must be zero or one")
        if self.operation == "oidc_jws_verification":
            if self.dispatch_count != 0 or self.algorithm != ALLOWED_JWS_ALGORITHM:
                raise EnterpriseIdentityRuntimeError("OIDC receipt shape is invalid")
            if any(
                value is None
                for value in (
                    self.key_id,
                    self.key_fingerprint_sha256,
                    self.keyset_id,
                    self.keyset_sha256,
                    self.assurance_context,
                )
            ):
                raise EnterpriseIdentityRuntimeError("OIDC receipt omits verification evidence")
            object.__setattr__(self, "key_id", _identifier(self.key_id, "receipt key_id"))
            object.__setattr__(
                self,
                "key_fingerprint_sha256",
                _digest(self.key_fingerprint_sha256, "receipt key_fingerprint_sha256"),
            )
            object.__setattr__(self, "keyset_id", _identifier(self.keyset_id, "receipt keyset_id"))
            object.__setattr__(
                self,
                "keyset_sha256",
                _digest(self.keyset_sha256, "receipt keyset_sha256"),
            )
            object.__setattr__(
                self,
                "assurance_context",
                _identifier(self.assurance_context, "receipt assurance_context"),
            )
            if self.replay_binding_sha256 is None or any(
                value is not None
                for value in (
                    self.idempotency_key,
                    self.admission_id,
                    self.admission_sha256,
                    self.admission_authenticator_id,
                    self.admission_authentication_sha256,
                    self.environment,
                    self.dispatcher_id,
                    self.dispatcher_attestation_sha256,
                    self.idempotency_store_id,
                    self.reservation_id,
                    self.reservation_sha256,
                    self.completion_id,
                    self.completion_sha256,
                )
            ):
                raise EnterpriseIdentityRuntimeError("OIDC receipt replay shape is invalid")
            object.__setattr__(
                self,
                "replay_binding_sha256",
                _digest(self.replay_binding_sha256, "receipt replay_binding_sha256"),
            )
        else:
            if self.dispatch_count != 1:
                raise EnterpriseIdentityRuntimeError("SCIM receipt must record one dispatch")
            if any(
                value is not None
                for value in (
                    self.algorithm,
                    self.key_id,
                    self.key_fingerprint_sha256,
                    self.keyset_id,
                    self.keyset_sha256,
                    self.assurance_context,
                    self.replay_binding_sha256,
                )
            ):
                raise EnterpriseIdentityRuntimeError("SCIM receipt contains OIDC-only fields")
            required_scim = (
                self.idempotency_key,
                self.admission_id,
                self.admission_sha256,
                self.admission_authenticator_id,
                self.admission_authentication_sha256,
                self.environment,
                self.dispatcher_id,
                self.dispatcher_attestation_sha256,
                self.idempotency_store_id,
                self.reservation_id,
                self.reservation_sha256,
                self.completion_id,
                self.completion_sha256,
            )
            if any(value is None for value in required_scim):
                raise EnterpriseIdentityRuntimeError("SCIM receipt omits dispatch evidence")
            object.__setattr__(
                self,
                "idempotency_key",
                _identifier(self.idempotency_key, "receipt idempotency_key"),
            )
            for name in (
                "admission_id",
                "admission_authenticator_id",
                "environment",
                "dispatcher_id",
                "idempotency_store_id",
                "reservation_id",
                "completion_id",
            ):
                object.__setattr__(
                    self,
                    name,
                    _identifier(getattr(self, name), f"receipt {name}"),
                )
            if self.environment not in {"test", "staging"}:
                raise EnterpriseIdentityRuntimeError("receipt environment must be non-production")
            for name in (
                "admission_sha256",
                "admission_authentication_sha256",
                "dispatcher_attestation_sha256",
                "reservation_sha256",
                "completion_sha256",
            ):
                object.__setattr__(
                    self,
                    name,
                    _digest(getattr(self, name), f"receipt {name}"),
                )
        receipt_id, digest = _identity("EIR", self.KIND, self._body())
        object.__setattr__(self, "receipt_id", receipt_id)
        object.__setattr__(self, "receipt_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "assurance_context": self.assurance_context,
            "decision_sha256": self.decision_sha256,
            "dispatch_count": self.dispatch_count,
            "effects": dict(NO_EFFECTS),
            "evaluated_at": self.evaluated_at,
            "evidence_sha256": self.evidence_sha256,
            "idempotency_key": self.idempotency_key,
            "key_id": self.key_id,
            "key_fingerprint_sha256": self.key_fingerprint_sha256,
            "keyset_id": self.keyset_id,
            "keyset_sha256": self.keyset_sha256,
            "kind": self.KIND,
            "operation": self.operation,
            "policy_sha256": self.policy_sha256,
            "replay_binding_sha256": self.replay_binding_sha256,
            "admission_id": self.admission_id,
            "admission_sha256": self.admission_sha256,
            "admission_authenticator_id": self.admission_authenticator_id,
            "admission_authentication_sha256": self.admission_authentication_sha256,
            "environment": self.environment,
            "dispatcher_id": self.dispatcher_id,
            "dispatcher_attestation_sha256": self.dispatcher_attestation_sha256,
            "idempotency_store_id": self.idempotency_store_id,
            "reservation_id": self.reservation_id,
            "reservation_sha256": self.reservation_sha256,
            "completion_id": self.completion_id,
            "completion_sha256": self.completion_sha256,
            "schema_version": SCHEMA_VERSION,
            "source_sha256": self.source_sha256,
            "status": self.status,
            "subject_id": self.subject_id,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


@dataclass(frozen=True)
class OidcVerificationOutcome:
    assertion: VerifiedSsoAssertion
    decision: IdentityDecision
    receipt: EnterpriseIdentityRuntimeReceipt


def verify_pinned_oidc_jws(
    token: str,
    policy: EnterpriseIdentityPolicy,
    *,
    keyset: AuthenticatedPinnedOidcKeyset,
    keyset_verifier: AuthenticatedOidcKeysetVerifier,
    evaluated_at: str,
    expected_subject_id: str | None = None,
    expected_nonce: str | None = None,
    seen_replay_ids: Sequence[str] = (),
    required_claims: Mapping[str, str] | None = None,
) -> OidcVerificationOutcome:
    """Verify and admit one compact RS256 OIDC token without external I/O."""

    if not isinstance(policy, EnterpriseIdentityPolicy):
        raise EnterpriseIdentityRuntimeError("policy is invalid")
    evaluated_at = _timestamp(evaluated_at, "evaluated_at")
    if (
        not isinstance(token, str)
        or not token.isascii()
        or len(token.encode("ascii")) > MAX_TOKEN_BYTES
    ):
        raise EnterpriseIdentityRuntimeError("OIDC token is not bounded printable ASCII")
    if any(character.isspace() for character in token):
        raise EnterpriseIdentityRuntimeError("OIDC token contains whitespace")
    parts = token.split(".")
    if len(parts) != 3:
        raise EnterpriseIdentityRuntimeError("OIDC token must be compact JWS")
    header_segment, claims_segment, signature_segment = parts
    header = _json_object(
        _b64url_decode(header_segment, "OIDC protected header", MAX_HEADER_BYTES),
        "OIDC protected header",
    )
    if set(header) != {"alg", "kid", "typ"}:
        raise EnterpriseIdentityRuntimeError("OIDC protected header has an unsupported shape")
    if header.get("alg") != ALLOWED_JWS_ALGORITHM or header.get("typ") != "JWT":
        raise EnterpriseIdentityRuntimeError("OIDC protected header algorithm or type is rejected")
    key_id = _identifier(header.get("kid"), "OIDC key ID")
    if not isinstance(keyset, AuthenticatedPinnedOidcKeyset):
        raise EnterpriseIdentityRuntimeError("authenticated pinned keyset is required")
    if (
        keyset.policy_sha256 != policy.record_sha256
        or keyset.issuer != policy.sso_trust.issuer
        or keyset.audience != policy.sso_trust.audience
    ):
        raise EnterpriseIdentityRuntimeError("OIDC keyset does not match policy")
    now = _instant(evaluated_at)
    if not (_instant(keyset.issued_at) <= now < _instant(keyset.expires_at)):
        raise EnterpriseIdentityRuntimeError("OIDC keyset is not active")
    verifier_id = _identifier(
        getattr(keyset_verifier, "verifier_id", None),
        "keyset verifier_id",
    )
    if verifier_id != keyset.authenticator_id:
        raise EnterpriseIdentityRuntimeError("OIDC keyset verifier identity does not match")
    verifier_method = getattr(keyset_verifier, "verify", None)
    if not callable(verifier_method):
        raise EnterpriseIdentityRuntimeError("OIDC keyset verifier is invalid")
    try:
        keyset_authenticated = verifier_method(keyset)
    except Exception as exc:
        raise EnterpriseIdentityRuntimeError("OIDC keyset authentication failed") from exc
    if keyset_authenticated is not True:
        raise EnterpriseIdentityRuntimeError("OIDC keyset authentication failed")
    key = keyset.public_keys.get(key_id)
    if key is None:
        raise EnterpriseIdentityRuntimeError("OIDC key ID is not pinned")
    key_fingerprint_sha256 = _rsa_spki_sha256(key)
    if keyset.key_fingerprints_sha256.get(key_id) != key_fingerprint_sha256:
        raise EnterpriseIdentityRuntimeError("OIDC key fingerprint is not pinned")
    signature = _b64url_decode(signature_segment, "OIDC signature", 1024)
    if len(signature) != key.key_size // 8:
        raise EnterpriseIdentityRuntimeError("OIDC signature size does not match the pinned key")
    signing_input = f"{header_segment}.{claims_segment}".encode("ascii")
    try:
        key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise EnterpriseIdentityRuntimeError("OIDC signature verification failed") from exc

    claims = _json_object(
        _b64url_decode(claims_segment, "OIDC claims", MAX_CLAIMS_BYTES),
        "OIDC claims",
    )
    if len(claims) > 64:
        raise EnterpriseIdentityRuntimeError("OIDC claims exceed the member limit")
    issuer = _string_claim(claims, "iss")
    audience = _string_claim(claims, "aud")
    subject_id = _string_claim(claims, "sub")
    tenant_id = _string_claim(claims, "tenant_id")
    assurance_context = _string_claim(claims, "acr")
    session_id = _string_claim(claims, "sid")
    if issuer != policy.sso_trust.issuer:
        raise EnterpriseIdentityRuntimeError("OIDC issuer does not match policy")
    if audience != policy.sso_trust.audience:
        raise EnterpriseIdentityRuntimeError("OIDC audience does not match policy")
    if tenant_id != policy.tenant_id:
        raise EnterpriseIdentityRuntimeError("OIDC tenant does not match policy")
    if expected_subject_id is not None:
        expected_subject_id = _identifier(expected_subject_id, "expected_subject_id")
        if subject_id != expected_subject_id:
            raise EnterpriseIdentityRuntimeError("OIDC subject does not match")
    if assurance_context not in policy.sso_trust.accepted_assurance_contexts:
        raise EnterpriseIdentityRuntimeError("OIDC assurance context is rejected")

    issued_at_epoch = _epoch(claims.get("iat"), "OIDC iat claim")
    expires_at_epoch = _epoch(claims.get("exp"), "OIDC exp claim")
    auth_time_epoch = _epoch(claims.get("auth_time"), "OIDC auth_time claim")
    not_before_epoch = _epoch(claims.get("nbf", issued_at_epoch), "OIDC nbf claim")
    if not auth_time_epoch <= issued_at_epoch < expires_at_epoch:
        raise EnterpriseIdentityRuntimeError("OIDC claim time ordering is invalid")
    now_epoch = int(_instant(evaluated_at).timestamp())
    skew = policy.sso_trust.clock_skew_seconds
    if issued_at_epoch > now_epoch + skew or not_before_epoch > now_epoch + skew:
        raise EnterpriseIdentityRuntimeError("OIDC token is not yet valid")
    if expires_at_epoch <= now_epoch - skew:
        raise EnterpriseIdentityRuntimeError("OIDC token is expired")

    methods = _string_list_claim(claims, "amr")
    mfa_present = "mfa" in methods
    if policy.sso_trust.require_mfa and not mfa_present:
        raise EnterpriseIdentityRuntimeError("OIDC token does not establish required MFA")
    if isinstance(seen_replay_ids, (str, bytes)) or not isinstance(seen_replay_ids, Sequence):
        raise EnterpriseIdentityRuntimeError("seen_replay_ids must be a sequence")
    replay_values = tuple(_identifier(value, "seen replay ID") for value in seen_replay_ids)
    if len(replay_values) > 100_000 or len(replay_values) != len(set(replay_values)):
        raise EnterpriseIdentityRuntimeError("seen_replay_ids is invalid")
    replay_set = frozenset(replay_values)
    if expected_nonce is not None:
        expected_nonce = _identifier(expected_nonce, "expected_nonce")
        if claims.get("nonce") != expected_nonce:
            raise EnterpriseIdentityRuntimeError("OIDC nonce does not match")
        replay_binding_sha256 = canonical_sha256({"mode": "nonce", "value": expected_nonce})
    else:
        replay_id = _string_claim(claims, "jti")
        if replay_id in replay_set:
            raise EnterpriseIdentityRuntimeError("OIDC replay ID was already observed")
        replay_binding_sha256 = canonical_sha256({"mode": "jti", "value": replay_id})
    _validate_required_claims(claims, required_claims or {})

    token_sha256 = "sha256:" + hashlib.sha256(token.encode("ascii")).hexdigest()
    verification_evidence_sha256 = canonical_sha256(
        {
            "algorithm": ALLOWED_JWS_ALGORITHM,
            "key_fingerprint_sha256": key_fingerprint_sha256,
            "key_id": key_id,
            "keyset_id": keyset.keyset_id,
            "keyset_sha256": keyset.keyset_sha256,
            "policy_sha256": policy.record_sha256,
            "replay_binding_sha256": replay_binding_sha256,
            "token_sha256": token_sha256,
        }
    )
    assertion = VerifiedSsoAssertion(
        tenant_id=tenant_id,
        issuer=issuer,
        audience=audience,
        subject_id=subject_id,
        auth_time=_epoch_timestamp(auth_time_epoch, "OIDC auth_time claim"),
        issued_at=_epoch_timestamp(issued_at_epoch, "OIDC iat claim"),
        expires_at=_epoch_timestamp(expires_at_epoch, "OIDC exp claim"),
        mfa_present=mfa_present,
        assurance_context=assurance_context,
        session_id=session_id,
        verification_evidence_sha256=verification_evidence_sha256,
    )
    decision = admit_sso_assertion(policy, assertion, evaluated_at=evaluated_at)
    if decision.decision != Decision.ALLOW:
        raise EnterpriseIdentityRuntimeError("OIDC assertion was denied by enterprise policy")
    receipt = EnterpriseIdentityRuntimeReceipt(
        operation="oidc_jws_verification",
        status="verified_and_admitted",
        tenant_id=tenant_id,
        subject_id=subject_id,
        evaluated_at=evaluated_at,
        policy_sha256=policy.record_sha256,
        source_sha256=token_sha256,
        evidence_sha256=assertion.record_sha256,
        decision_sha256=decision.record_sha256,
        dispatch_count=0,
        algorithm=ALLOWED_JWS_ALGORITHM,
        key_id=key_id,
        key_fingerprint_sha256=key_fingerprint_sha256,
        keyset_id=keyset.keyset_id,
        keyset_sha256=keyset.keyset_sha256,
        assurance_context=assurance_context,
        replay_binding_sha256=replay_binding_sha256,
    )
    return OidcVerificationOutcome(assertion, decision, receipt)


@dataclass(frozen=True)
class ProvisioningDispatchAdmission:
    """Explicit non-production admission bound to one validated command."""

    tenant_id: str
    policy_sha256: str
    command_sha256: str
    decision_sha256: str
    idempotency_key: str
    environment: str
    dispatcher_id: str
    dispatcher_attestation_sha256: str
    idempotency_store_id: str
    approval_verifier_id: str
    approval_authentication_sha256: str
    issued_at: str
    expires_at: str
    approved: bool
    admission_id: str = field(init=False)
    admission_sha256: str = field(init=False)

    KIND: ClassVar[str] = ADMISSION_KIND

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "admission tenant_id"))
        for name in ("policy_sha256", "command_sha256", "decision_sha256"):
            object.__setattr__(self, name, _digest(getattr(self, name), f"admission {name}"))
        object.__setattr__(
            self,
            "idempotency_key",
            _identifier(self.idempotency_key, "admission idempotency_key"),
        )
        if self.environment not in {"test", "staging"}:
            raise EnterpriseIdentityRuntimeError("admission environment must be non-production")
        for name in ("dispatcher_id", "idempotency_store_id", "approval_verifier_id"):
            object.__setattr__(
                self,
                name,
                _identifier(getattr(self, name), f"admission {name}"),
            )
        for name in ("dispatcher_attestation_sha256", "approval_authentication_sha256"):
            object.__setattr__(
                self,
                name,
                _digest(getattr(self, name), f"admission {name}"),
            )
        object.__setattr__(self, "issued_at", _timestamp(self.issued_at, "admission issued_at"))
        object.__setattr__(self, "expires_at", _timestamp(self.expires_at, "admission expires_at"))
        if _instant(self.expires_at) <= _instant(self.issued_at):
            raise EnterpriseIdentityRuntimeError("admission validity interval is empty")
        if self.approved is not True:
            raise EnterpriseIdentityRuntimeError("dispatch admission must be explicitly approved")
        admission_id, digest = _identity("EIA", self.KIND, self._body())
        object.__setattr__(self, "admission_id", admission_id)
        object.__setattr__(self, "admission_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "command_sha256": self.command_sha256,
            "decision_sha256": self.decision_sha256,
            "dispatcher_attestation_sha256": self.dispatcher_attestation_sha256,
            "dispatcher_id": self.dispatcher_id,
            "environment": self.environment,
            "expires_at": self.expires_at,
            "idempotency_key": self.idempotency_key,
            "issued_at": self.issued_at,
            "idempotency_store_id": self.idempotency_store_id,
            "kind": self.KIND,
            "policy_sha256": self.policy_sha256,
            "approval_authentication_sha256": self.approval_authentication_sha256,
            "approval_verifier_id": self.approval_verifier_id,
            "schema_version": SCHEMA_VERSION,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "admission_id": self.admission_id,
            "admission_sha256": self.admission_sha256,
        }


class AuthenticatedAdmissionVerifier(Protocol):
    """Injected verifier for an authenticated dispatch admission."""

    verifier_id: str

    def verify(self, admission: ProvisioningDispatchAdmission) -> bool:
        """Return true only after authenticating the exact admission content."""


@dataclass(frozen=True)
class ScimDispatchResult:
    """Minimal postcondition report returned by the injected dispatcher."""

    tenant_id: str
    command_sha256: str
    idempotency_key: str
    operation: str
    resource_kind: str
    resource_sha256: str
    resulting_version: int
    applied: bool
    tombstone_confirmed: bool
    session_revocation_confirmed: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "result tenant_id"))
        object.__setattr__(self, "command_sha256", _digest(self.command_sha256, "result command"))
        object.__setattr__(
            self,
            "idempotency_key",
            _identifier(self.idempotency_key, "result idempotency_key"),
        )
        if self.operation not in {item.value for item in ProvisioningOperation}:
            raise EnterpriseIdentityRuntimeError("result operation is invalid")
        if self.resource_kind not in {"user", "group", "membership"}:
            raise EnterpriseIdentityRuntimeError("result resource_kind is invalid")
        object.__setattr__(
            self, "resource_sha256", _digest(self.resource_sha256, "result resource_sha256")
        )
        if isinstance(self.resulting_version, bool) or not isinstance(self.resulting_version, int):
            raise EnterpriseIdentityRuntimeError("result resulting_version must be an integer")
        if not all(
            isinstance(value, bool)
            for value in (
                self.applied,
                self.tombstone_confirmed,
                self.session_revocation_confirmed,
            )
        ):
            raise EnterpriseIdentityRuntimeError("result flags must be boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "applied": self.applied,
            "command_sha256": self.command_sha256,
            "idempotency_key": self.idempotency_key,
            "operation": self.operation,
            "resource_kind": self.resource_kind,
            "resource_sha256": self.resource_sha256,
            "resulting_version": self.resulting_version,
            "session_revocation_confirmed": self.session_revocation_confirmed,
            "tenant_id": self.tenant_id,
            "tombstone_confirmed": self.tombstone_confirmed,
        }


@dataclass(frozen=True)
class ScimIdempotencyReservation:
    """Atomic reservation evidence returned before external dispatch."""

    store_id: str
    reservation_token: str
    idempotency_key: str
    command_sha256: str
    admission_sha256: str
    dispatcher_id: str
    environment: str
    reserved_at: str
    reservation_id: str = field(init=False)
    reservation_sha256: str = field(init=False)

    KIND: ClassVar[str] = RESERVATION_KIND

    def __post_init__(self) -> None:
        for name in ("store_id", "reservation_token", "idempotency_key", "dispatcher_id"):
            object.__setattr__(
                self,
                name,
                _identifier(getattr(self, name), f"reservation {name}"),
            )
        for name in ("command_sha256", "admission_sha256"):
            object.__setattr__(
                self,
                name,
                _digest(getattr(self, name), f"reservation {name}"),
            )
        if self.environment not in {"test", "staging"}:
            raise EnterpriseIdentityRuntimeError("reservation environment must be non-production")
        object.__setattr__(
            self,
            "reserved_at",
            _timestamp(self.reserved_at, "reservation reserved_at"),
        )
        reservation_id, digest = _identity("EIRR", self.KIND, self._body())
        object.__setattr__(self, "reservation_id", reservation_id)
        object.__setattr__(self, "reservation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "admission_sha256": self.admission_sha256,
            "command_sha256": self.command_sha256,
            "dispatcher_id": self.dispatcher_id,
            "environment": self.environment,
            "idempotency_key": self.idempotency_key,
            "kind": self.KIND,
            "reservation_token": self.reservation_token,
            "reserved_at": self.reserved_at,
            "schema_version": SCHEMA_VERSION,
            "store_id": self.store_id,
        }


@dataclass(frozen=True)
class ScimIdempotencyCompletion:
    """Atomic completion evidence returned after exact postconditions pass."""

    store_id: str
    reservation_sha256: str
    result_sha256: str
    completed_at: str
    completion_id: str = field(init=False)
    completion_sha256: str = field(init=False)

    KIND: ClassVar[str] = COMPLETION_KIND

    def __post_init__(self) -> None:
        object.__setattr__(self, "store_id", _identifier(self.store_id, "completion store_id"))
        for name in ("reservation_sha256", "result_sha256"):
            object.__setattr__(
                self,
                name,
                _digest(getattr(self, name), f"completion {name}"),
            )
        object.__setattr__(
            self,
            "completed_at",
            _timestamp(self.completed_at, "completion completed_at"),
        )
        completion_id, digest = _identity("EIRC", self.KIND, self._body())
        object.__setattr__(self, "completion_id", completion_id)
        object.__setattr__(self, "completion_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "completed_at": self.completed_at,
            "kind": self.KIND,
            "reservation_sha256": self.reservation_sha256,
            "result_sha256": self.result_sha256,
            "schema_version": SCHEMA_VERSION,
            "store_id": self.store_id,
        }


class AttestedScimDispatcher(Protocol):
    """Injected environment-attested non-production SCIM dispatcher."""

    dispatcher_id: str
    environment: str
    attestation_sha256: str

    def dispatch(self, command: ProvisioningCommand) -> ScimDispatchResult:
        """Dispatch the admitted command exactly once."""


class AtomicScimIdempotencyStore(Protocol):
    """Injected store that atomically reserves and completes SCIM keys."""

    store_id: str

    def reserve(
        self,
        *,
        idempotency_key: str,
        command_sha256: str,
        admission_sha256: str,
        dispatcher_id: str,
        environment: str,
        reserved_at: str,
    ) -> ScimIdempotencyReservation | None:
        """Atomically reserve a new key, or return none for replay or contention."""

    def complete(
        self,
        reservation: ScimIdempotencyReservation,
        *,
        result_sha256: str,
        completed_at: str,
    ) -> ScimIdempotencyCompletion:
        """Atomically complete the exact held reservation."""


ScimDispatcher = AttestedScimDispatcher


@dataclass(frozen=True)
class ScimDispatchOutcome:
    decision: IdentityDecision
    result: ScimDispatchResult
    receipt: EnterpriseIdentityRuntimeReceipt


def dispatch_validated_provisioning(
    policy: EnterpriseIdentityPolicy,
    command: ProvisioningCommand,
    *,
    actor_binding: RoleBinding | None,
    current_version: int | None,
    current_sha256: str | None,
    seen_idempotency: Mapping[str, str],
    evaluated_at: str,
    admission: ProvisioningDispatchAdmission,
    admission_verifier: AuthenticatedAdmissionVerifier,
    dispatcher: AttestedScimDispatcher,
    idempotency_store: AtomicScimIdempotencyStore,
) -> ScimDispatchOutcome:
    """Dispatch one admitted non-production command through an injected boundary."""

    if not isinstance(policy, EnterpriseIdentityPolicy) or not isinstance(
        command, ProvisioningCommand
    ):
        raise EnterpriseIdentityRuntimeError("policy or provisioning command is invalid")
    if actor_binding is not None and not isinstance(actor_binding, RoleBinding):
        raise EnterpriseIdentityRuntimeError("actor_binding is invalid")
    if not isinstance(seen_idempotency, Mapping):
        raise EnterpriseIdentityRuntimeError("seen_idempotency must be a mapping")
    evaluated_at = _timestamp(evaluated_at, "evaluated_at")
    if command.tenant_id != policy.tenant_id:
        raise EnterpriseIdentityRuntimeError("provisioning tenant does not match policy")
    decision = validate_provisioning_command(
        policy,
        command,
        actor_binding=actor_binding,
        current_version=current_version,
        current_sha256=current_sha256,
        seen_idempotency=seen_idempotency,
        evaluated_at=evaluated_at,
    )
    if decision.decision != Decision.ALLOW:
        raise EnterpriseIdentityRuntimeError("provisioning command was denied")
    if not isinstance(admission, ProvisioningDispatchAdmission):
        raise EnterpriseIdentityRuntimeError("provisioning dispatch admission is invalid")
    expected = (
        admission.tenant_id == policy.tenant_id
        and admission.policy_sha256 == policy.record_sha256
        and admission.command_sha256 == command.record_sha256
        and admission.decision_sha256 == decision.record_sha256
        and admission.idempotency_key == command.idempotency_key
    )
    if not expected:
        raise EnterpriseIdentityRuntimeError("provisioning dispatch admission does not match")
    now = _instant(evaluated_at)
    if not (_instant(admission.issued_at) <= now < _instant(admission.expires_at)):
        raise EnterpriseIdentityRuntimeError("provisioning dispatch admission is not active")
    if command.idempotency_key in seen_idempotency:
        raise EnterpriseIdentityRuntimeError("provisioning idempotency key was already observed")
    admission_verifier_id = _identifier(
        getattr(admission_verifier, "verifier_id", None),
        "admission verifier_id",
    )
    if admission_verifier_id != admission.approval_verifier_id:
        raise EnterpriseIdentityRuntimeError("admission verifier identity does not match")
    admission_verify = getattr(admission_verifier, "verify", None)
    if not callable(admission_verify):
        raise EnterpriseIdentityRuntimeError("admission verifier is invalid")
    try:
        admission_authenticated = admission_verify(admission)
    except Exception as exc:
        raise EnterpriseIdentityRuntimeError("dispatch admission authentication failed") from exc
    if admission_authenticated is not True:
        raise EnterpriseIdentityRuntimeError("dispatch admission authentication failed")

    dispatcher_id = _identifier(getattr(dispatcher, "dispatcher_id", None), "dispatcher_id")
    dispatcher_environment = getattr(dispatcher, "environment", None)
    dispatcher_attestation = _digest(
        getattr(dispatcher, "attestation_sha256", None),
        "dispatcher attestation_sha256",
    )
    dispatch_method = getattr(dispatcher, "dispatch", None)
    if not callable(dispatch_method):
        raise EnterpriseIdentityRuntimeError("dispatcher protocol is invalid")
    if (
        dispatcher_id != admission.dispatcher_id
        or dispatcher_environment != admission.environment
        or dispatcher_attestation != admission.dispatcher_attestation_sha256
    ):
        raise EnterpriseIdentityRuntimeError("dispatcher identity or attestation does not match")

    store_id = _identifier(getattr(idempotency_store, "store_id", None), "idempotency store_id")
    if store_id != admission.idempotency_store_id:
        raise EnterpriseIdentityRuntimeError("idempotency store identity does not match")
    reserve_method = getattr(idempotency_store, "reserve", None)
    complete_method = getattr(idempotency_store, "complete", None)
    if not callable(reserve_method) or not callable(complete_method):
        raise EnterpriseIdentityRuntimeError("atomic idempotency store protocol is invalid")
    try:
        reservation = reserve_method(
            idempotency_key=command.idempotency_key,
            command_sha256=command.record_sha256,
            admission_sha256=admission.admission_sha256,
            dispatcher_id=dispatcher_id,
            environment=admission.environment,
            reserved_at=evaluated_at,
        )
    except Exception as exc:
        raise EnterpriseIdentityRuntimeError("SCIM idempotency reservation failed") from exc
    if reservation is None:
        raise EnterpriseIdentityRuntimeError("SCIM idempotency key is reserved or completed")
    if not isinstance(reservation, ScimIdempotencyReservation):
        raise EnterpriseIdentityRuntimeError("SCIM idempotency reservation is invalid")
    exact_reservation = (
        reservation.store_id == store_id
        and reservation.idempotency_key == command.idempotency_key
        and reservation.command_sha256 == command.record_sha256
        and reservation.admission_sha256 == admission.admission_sha256
        and reservation.dispatcher_id == dispatcher_id
        and reservation.environment == admission.environment
        and reservation.reserved_at == evaluated_at
    )
    if not exact_reservation:
        raise EnterpriseIdentityRuntimeError("SCIM idempotency reservation does not match")

    try:
        result = dispatch_method(command)
    except Exception as exc:
        raise EnterpriseIdentityRuntimeError("injected SCIM dispatcher failed") from exc
    if not isinstance(result, ScimDispatchResult):
        raise EnterpriseIdentityRuntimeError("injected SCIM dispatcher returned an invalid result")
    exact_postconditions = (
        result.tenant_id == command.tenant_id
        and result.command_sha256 == command.record_sha256
        and result.idempotency_key == command.idempotency_key
        and result.operation == command.operation
        and result.resource_kind == command.resource_kind
        and result.resulting_version == command.new_version
        and result.applied
        and result.tombstone_confirmed == command.tombstone_required
        and result.session_revocation_confirmed == command.session_revocation_required
    )
    if not exact_postconditions:
        raise EnterpriseIdentityRuntimeError("SCIM dispatch postconditions failed")
    result_sha256 = canonical_sha256(result.to_dict())
    try:
        completion = complete_method(
            reservation,
            result_sha256=result_sha256,
            completed_at=evaluated_at,
        )
    except Exception as exc:
        raise EnterpriseIdentityRuntimeError("SCIM idempotency completion failed") from exc
    if not isinstance(completion, ScimIdempotencyCompletion):
        raise EnterpriseIdentityRuntimeError("SCIM idempotency completion is invalid")
    if (
        completion.store_id != store_id
        or completion.reservation_sha256 != reservation.reservation_sha256
        or completion.result_sha256 != result_sha256
        or completion.completed_at != evaluated_at
    ):
        raise EnterpriseIdentityRuntimeError("SCIM idempotency completion does not match")
    receipt = EnterpriseIdentityRuntimeReceipt(
        operation="scim_dispatch",
        status="dispatched_non_production",
        tenant_id=command.tenant_id,
        subject_id=command.actor_subject_id,
        evaluated_at=evaluated_at,
        policy_sha256=policy.record_sha256,
        source_sha256=command.record_sha256,
        evidence_sha256=result.resource_sha256,
        decision_sha256=decision.record_sha256,
        dispatch_count=1,
        idempotency_key=command.idempotency_key,
        admission_id=admission.admission_id,
        admission_sha256=admission.admission_sha256,
        admission_authenticator_id=admission.approval_verifier_id,
        admission_authentication_sha256=admission.approval_authentication_sha256,
        environment=admission.environment,
        dispatcher_id=dispatcher_id,
        dispatcher_attestation_sha256=dispatcher_attestation,
        idempotency_store_id=store_id,
        reservation_id=reservation.reservation_id,
        reservation_sha256=reservation.reservation_sha256,
        completion_id=completion.completion_id,
        completion_sha256=completion.completion_sha256,
    )
    return ScimDispatchOutcome(decision, result, receipt)


__all__ = [
    "ADMISSION_KIND",
    "ALLOWED_JWS_ALGORITHM",
    "COMPLETION_KIND",
    "KEYSET_KIND",
    "NO_EFFECTS",
    "RECEIPT_KIND",
    "RESERVATION_KIND",
    "AtomicScimIdempotencyStore",
    "AttestedScimDispatcher",
    "AuthenticatedAdmissionVerifier",
    "AuthenticatedOidcKeysetVerifier",
    "AuthenticatedPinnedOidcKeyset",
    "EnterpriseIdentityRuntimeError",
    "EnterpriseIdentityRuntimeReceipt",
    "OidcVerificationOutcome",
    "ProvisioningDispatchAdmission",
    "ScimDispatchOutcome",
    "ScimDispatchResult",
    "ScimDispatcher",
    "ScimIdempotencyCompletion",
    "ScimIdempotencyReservation",
    "dispatch_validated_provisioning",
    "verify_pinned_oidc_jws",
]
