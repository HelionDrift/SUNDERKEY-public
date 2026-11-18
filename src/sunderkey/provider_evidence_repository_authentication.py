"""Principal authentication for provider evidence repository receipts."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .collaboration_executor import (
    SAFETY_REDUCING_OPERATIONS,
    CollaborationExecutorAcknowledgement,
    CollaborationExecutorDispatchEnvelope,
    validate_collaboration_executor_acknowledgement,
)
from .collaboration_executor_authentication import (
    AuthenticatedCollaborationExecutorAcknowledgement,
    collaboration_executor_acknowledgement_selection_sha256,
)
from .collaboration_executor_provider_report import CollaborationExecutorProviderReport
from .collaboration_executor_provider_report_authentication import (
    AuthenticatedCollaborationExecutorProviderReport,
    validate_authenticated_collaboration_executor_provider_report_document,
)
from .errors import PrincipalAuthenticationError, SunderkeyError
from .events import MISSION_ID_PATTERN, PROFILE_ID_PATTERN
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    VerifiedPrincipal,
    VerifiedScopeGrant,
    VerifiedTrustPolicy,
    compute_operation_intent_hash,
    verify_principal_assertion,
)
from .provider_evidence_lifecycle import ProviderEvidenceLifecyclePolicy
from .provider_evidence_repository import (
    ProviderEvidenceRepositoryIngestReceipt,
    ProviderEvidenceRepositoryIngestRequest,
    validate_provider_evidence_repository_ingest_receipt,
)
from .qualification import _canonical_json, _canonical_sha256
from .store import parse_timestamp

SCHEMA_VERSION = 1
AUTHENTICATION_DOMAIN = "sunderkey.provider-evidence-repository-ingest-authentication.v1"
SELECTION_DOMAIN = "sunderkey.provider-evidence-repository-ingest-receipt-selection.v1"
_PROOF_KEY = secrets.token_bytes(32)
MAXIMUM_AUTHENTICATION_BYTES = 1_048_576
_MAXIMUM_NODES = 32_768
_MAXIMUM_DEPTH = 32
_MAXIMUM_STRING = 8192
_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_INTEGER_FIELDS = frozenset(
    {
        "schema_version",
        "policy_version",
        "evidence_size_bytes",
        "operation_sequence",
        "owner_epoch",
        "fence_generation",
        "retention_seconds",
        "deletion_deadline_seconds",
        "maximum_access_seconds",
        "minimum_replica_count",
    }
)
_BOUNDARY = {
    "authentication_status": "authenticated_expected_repository_principal",
    "lifecycle_policy_status": "prepared_policy_bound_not_activated",
    "repository_control_status": "provider_assertions_not_independently_verified",
    "external_effect_status": "authenticated_report_unverified_effect",
    "dedicated_identity_status": (
        "expected_identity_authenticated_deployment_dedication_unverified"
    ),
    "evidence_custody_status": "provider_report_only",
    "raw_evidence_in_contract": False,
    "runtime_effect": "none",
}
_PRINCIPAL_FIELDS = frozenset(
    {
        "assertion_id",
        "assertion_sha256",
        "subject",
        "profile_id",
        "issuer",
        "key_id",
        "key_sha256",
        "policy_id",
        "policy_version",
        "policy_sha256",
        "scope_grant_id",
        "scope_grant_sha256",
        "audience",
        "store_id",
        "mission_id",
        "operation",
        "operation_intent_sha256",
        "authenticated_at",
        "expires_at",
    }
)


def _bounded_native(value: Any) -> None:
    """Charge the complete ASCII JSON tree before serialization or source replay."""
    remaining = MAXIMUM_AUTHENTICATION_BYTES
    nodes = 0

    def charge(amount: int) -> None:
        nonlocal remaining
        remaining -= amount
        if remaining < 0:
            raise PrincipalAuthenticationError("Repository authentication exceeds its byte bound")

    def text_size(item: str) -> None:
        if len(item) > _MAXIMUM_STRING:
            raise PrincipalAuthenticationError("Repository authentication string exceeds its bound")
        charge(2)
        for character in item:
            point = ord(character)
            charge(
                2
                if character in '"\\' or character in "\b\f\n\r\t"
                else 6
                if point < 32 or 127 <= point <= 65535
                else 12
                if point > 65535
                else 1
            )

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > _MAXIMUM_DEPTH or nodes > _MAXIMUM_NODES:
            raise PrincipalAuthenticationError("Repository authentication exceeds its tree bound")
        kind = type(item)
        if kind is dict:
            charge(2 + max(0, len(item) - 1) + len(item))
            for key, child in item.items():
                if type(key) is not str:
                    raise PrincipalAuthenticationError(
                        "Repository authentication keys must be native strings"
                    )
                text_size(key)
                if key in _INTEGER_FIELDS and type(child) is not int:
                    raise PrincipalAuthenticationError(f"{key} must be a native integer")
                visit(child, depth + 1)
        elif kind is list:
            charge(2 + max(0, len(item) - 1))
            for child in item:
                visit(child, depth + 1)
        elif kind is str:
            text_size(item)
        elif kind is bool:
            charge(4 if item else 5)
        elif kind is int:
            if not -(2**63) <= item < 2**63:
                raise PrincipalAuthenticationError(
                    "Repository authentication integer exceeds its bound"
                )
            charge(len(str(item)))
        elif item is None:
            charge(4)
        else:
            raise PrincipalAuthenticationError(
                "Repository authentication requires native JSON primitives"
            )

    visit(value, 0)


def _native_document_json(text: Any) -> dict[str, Any]:
    if type(text) is not str or len(text) > MAXIMUM_AUTHENTICATION_BYTES:
        raise PrincipalAuthenticationError("Repository source JSON must be a bounded native string")
    try:
        if len(text.encode("utf-8")) > MAXIMUM_AUTHENTICATION_BYTES:
            raise PrincipalAuthenticationError("Repository source JSON exceeds its byte bound")
    except UnicodeError as exc:
        raise PrincipalAuthenticationError("Repository source JSON must be UTF-8") from exc

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in items:
            if key in result:
                raise PrincipalAuthenticationError("Repository source JSON contains duplicate keys")
            result[key] = child
        return result

    def integer(text: str) -> int:
        if len(text) > 20:
            raise PrincipalAuthenticationError("Repository source integer exceeds its bound")
        return int(text)

    def unsupported(_: str) -> Any:
        raise PrincipalAuthenticationError(
            "Repository source JSON does not support floating-point values"
        )

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
        if type(value) is not dict:
            raise PrincipalAuthenticationError("Repository source JSON must be an object")
        _bounded_native(value)
        return value
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise PrincipalAuthenticationError("Repository source is not bounded strict JSON") from exc


def _fields(value: Any, expected: set[str] | frozenset[str], label: str) -> None:
    if type(value) is not dict or set(value) != expected:
        raise PrincipalAuthenticationError(f"{label} fields are invalid")


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise PrincipalAuthenticationError(f"{label} requires native canonical SHA-256")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise PrincipalAuthenticationError(f"{label} requires a native identifier")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise PrincipalAuthenticationError(f"{label} requires native canonical UTC")
    try:
        return parse_timestamp(value, label)
    except (SunderkeyError, ValueError, TypeError) as exc:
        raise PrincipalAuthenticationError(f"{label} is invalid") from exc


def _capture_wrapper(value: Any, family: type, id_field: str, hash_field: str) -> dict[str, Any]:
    if type(value) is not family:
        raise PrincipalAuthenticationError("Repository source requires its exact wrapper family")
    identifier = getattr(value, id_field)
    if type(identifier) is not str:
        raise PrincipalAuthenticationError("Repository wrapper identity must be a native string")
    digest = _digest(getattr(value, hash_field), hash_field)
    document = _native_document_json(value.document_json)
    if document.get(id_field) != identifier or document.get(hash_field) != digest:
        raise PrincipalAuthenticationError(
            "Repository wrapper metadata does not match its document"
        )
    if _canonical_json(document) != value.document_json:
        raise PrincipalAuthenticationError("Repository wrapper source JSON is not canonical")
    return document


def _rebuild(family: type, raw: dict[str, Any]) -> Any:
    try:
        rebuilt = family.from_dict(raw)
        if _canonical_json(rebuilt.to_dict()) != _canonical_json(raw):
            raise PrincipalAuthenticationError(
                "Repository source normalization changed its content"
            )
        return rebuilt
    except (SunderkeyError, TypeError, ValueError, AttributeError, KeyError) as exc:
        raise PrincipalAuthenticationError(
            "Repository source does not reproduce its contract"
        ) from exc


def _principal_snapshot(principal: Any) -> dict[str, Any]:
    if (
        type(principal) is not VerifiedPrincipal
        or type(principal.operation) is not PrincipalOperation
    ):
        raise PrincipalAuthenticationError(
            "Repository principal requires the exact verified family"
        )
    # The exact family's to_dict only copies scalar fields and the checked enum.
    value = principal.to_dict()
    _bounded_native(value)
    if type(principal._proof) is not bytes or len(principal._proof) != 32:
        raise PrincipalAuthenticationError("Repository principal proof is invalid")
    return value


def _source_snapshot(source: Any) -> dict[str, Any]:
    if type(source) is dict:
        _bounded_native(source)
        return source
    if type(source) is not AuthenticatedCollaborationExecutorProviderReport:
        raise PrincipalAuthenticationError(
            "Source authentication requires its exact family or native object"
        )
    report = _capture_wrapper(
        source.provider_report,
        CollaborationExecutorProviderReport,
        "report_custody_id",
        "report_custody_sha256",
    )
    authentication = source.acknowledgement_authentication
    if type(authentication) is not AuthenticatedCollaborationExecutorAcknowledgement:
        raise PrincipalAuthenticationError(
            "Source acknowledgement authentication family is invalid"
        )
    if any(
        type(item._proof) is not bytes or len(item._proof) != 32
        for item in (source, authentication)
    ):
        raise PrincipalAuthenticationError("Source authentication proof is invalid")
    acknowledgement = _capture_wrapper(
        authentication.acknowledgement,
        CollaborationExecutorAcknowledgement,
        "acknowledgement_id",
        "acknowledgement_sha256",
    )
    document = {
        "schema_version": 1,
        "provider_report": report,
        "acknowledgement_authentication": {
            "schema_version": 1,
            "acknowledgement": acknowledgement,
            "worker_attestor": _principal_snapshot(authentication.worker_attestor),
            "authenticated_at": authentication.authenticated_at,
            "authentication_status": "authenticated_worker_principal",
            "external_effect_status": "authenticated_report_unverified_effect",
            "runtime_effect": "none",
            "authentication_id": authentication.authentication_id,
            "authentication_sha256": authentication.authentication_sha256,
        },
        "authentication_status": "authenticated_worker_principal",
        "evidence_verification_status": "provider_evidence_digest_unverified",
        "external_effect_status": "authenticated_report_unverified_effect",
        "runtime_effect": "none",
        "report_authentication_id": source.report_authentication_id,
        "report_authentication_sha256": source.report_authentication_sha256,
    }
    _bounded_native(document)
    return document


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    if not callable(clock):
        raise PrincipalAuthenticationError("clock must be callable")
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise PrincipalAuthenticationError("clock must return a timezone-aware datetime")
    return now.astimezone(UTC).replace(microsecond=0)


def _principal_document(principal: VerifiedPrincipal) -> dict[str, Any]:
    if not isinstance(principal, VerifiedPrincipal) or not principal._proof_is_valid():
        raise TypeError("principal must be produced by verify_principal_assertion")
    return principal.to_dict()


def _proof(document: dict[str, Any]) -> bytes:
    return hmac.new(
        _PROOF_KEY,
        (AUTHENTICATION_DOMAIN + "\x00" + _canonical_json(document)).encode(),
        "sha256",
    ).digest()


def provider_evidence_repository_ingest_receipt_selection_sha256(
    receipt: ProviderEvidenceRepositoryIngestReceipt,
) -> str:
    """Bind the exact repository-provider receipt selected for authentication."""

    raw = _capture_wrapper(
        receipt, ProviderEvidenceRepositoryIngestReceipt, "receipt_id", "receipt_sha256"
    )
    parsed = _rebuild(ProviderEvidenceRepositoryIngestReceipt, raw)
    return _canonical_sha256(
        {
            "domain": SELECTION_DOMAIN,
            "ingest_receipt": parsed.to_dict(),
        }
    )


def _authentication_body(
    request: ProviderEvidenceRepositoryIngestRequest,
    receipt: ProviderEvidenceRepositoryIngestReceipt,
    lifecycle_policy: ProviderEvidenceLifecyclePolicy,
    source_report_authentication: dict[str, Any],
    source_dispatch: CollaborationExecutorDispatchEnvelope,
    repository_attestor: VerifiedPrincipal,
    authenticated_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "ingest_request": request.to_dict(),
        "ingest_receipt": receipt.to_dict(),
        "lifecycle_policy": lifecycle_policy.to_dict(),
        "source_report_authentication": source_report_authentication,
        "source_dispatch": source_dispatch.to_dict(),
        "repository_attestor": _principal_document(repository_attestor),
        "authenticated_at": authenticated_at,
        "authentication_status": "authenticated_expected_repository_principal",
        "lifecycle_policy_status": "prepared_policy_bound_not_activated",
        "repository_control_status": "provider_assertions_not_independently_verified",
        "external_effect_status": "authenticated_report_unverified_effect",
        "dedicated_identity_status": (
            "expected_identity_authenticated_deployment_dedication_unverified"
        ),
        "evidence_custody_status": "provider_report_only",
        "raw_evidence_in_contract": False,
        "runtime_effect": "none",
    }


@dataclass(frozen=True)
class AuthenticatedProviderEvidenceRepositoryIngestReceipt:
    """An exact repository receipt authenticated by an authorized principal."""

    authentication_id: str
    authentication_sha256: str
    ingest_request: ProviderEvidenceRepositoryIngestRequest
    ingest_receipt: ProviderEvidenceRepositoryIngestReceipt
    lifecycle_policy: ProviderEvidenceLifecyclePolicy
    source_report_authentication: dict[str, Any]
    source_dispatch: CollaborationExecutorDispatchEnvelope
    repository_attestor: VerifiedPrincipal
    authenticated_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        body = _authentication_body(
            self.ingest_request,
            self.ingest_receipt,
            self.lifecycle_policy,
            self.source_report_authentication,
            self.source_dispatch,
            self.repository_attestor,
            self.authenticated_at,
        )
        digest = _canonical_sha256({"domain": AUTHENTICATION_DOMAIN, "authentication": body})
        expected_id = "ERI-" + digest.removeprefix("sha256:")[:32].upper()
        document = {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }
        if self.authentication_sha256 != digest or self.authentication_id != expected_id:
            raise TypeError("Authenticated repository receipt identity is invalid")
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            _proof(document),
        ):
            raise TypeError(
                "AuthenticatedProviderEvidenceRepositoryIngestReceipt can be "
                "created only by authenticate_provider_evidence_repository_ingest_receipt"
            )

    def to_dict(self) -> dict[str, Any]:
        body = _authentication_body(
            self.ingest_request,
            self.ingest_receipt,
            self.lifecycle_policy,
            self.source_report_authentication,
            self.source_dispatch,
            self.repository_attestor,
            self.authenticated_at,
        )
        return {
            **body,
            "authentication_id": self.authentication_id,
            "authentication_sha256": self.authentication_sha256,
        }

    def _proof_is_valid(self) -> bool:
        return isinstance(self._proof, bytes) and hmac.compare_digest(
            self._proof,
            _proof(self.to_dict()),
        )


def _validate_lifecycle_binding(
    request: ProviderEvidenceRepositoryIngestRequest,
    lifecycle_policy: ProviderEvidenceLifecyclePolicy,
) -> tuple[dict[str, Any], dict[str, Any]]:
    request_document = request.to_dict()
    policy_document = lifecycle_policy.to_dict()
    expected_lifecycle = {
        "retention_policy_id": lifecycle_policy.policy_id,
        "retention_policy_sha256": lifecycle_policy.policy_sha256,
        "residency_policy_id": policy_document["residency"]["policy_id"],
        "residency_policy_sha256": policy_document["residency"]["policy_sha256"],
        "encryption_profile_id": policy_document["encryption"]["profile_id"],
        "encryption_profile_sha256": policy_document["encryption"]["profile_sha256"],
        "access_policy_id": policy_document["access"]["policy_id"],
        "access_policy_sha256": policy_document["access"]["policy_sha256"],
    }
    if request_document["lifecycle_bindings"] != expected_lifecycle:
        raise PrincipalAuthenticationError(
            "Evidence ingest request lifecycle binding does not match the policy"
        )
    if request_document["custody_decision"] != policy_document["custody_decision"]:
        raise PrincipalAuthenticationError(
            "Evidence ingest request custody decision does not match the policy"
        )
    if parse_timestamp(
        request_document["requested_at"],
        "ingest_request.requested_at",
    ) < parse_timestamp(policy_document["created_at"], "lifecycle_policy.created_at"):
        raise PrincipalAuthenticationError(
            "Evidence lifecycle policy was created after the ingest request"
        )
    return request_document, policy_document


def _validate_principal_document(
    principal: Any,
    *,
    operation: PrincipalOperation,
    intent: dict[str, str],
    authenticated_at: str,
) -> None:
    _fields(principal, _PRINCIPAL_FIELDS, "Serialized repository/source principal")
    for name in _PRINCIPAL_FIELDS:
        value = principal[name]
        if name.endswith("_sha256"):
            _digest(value, name)
        elif name == "policy_version":
            if type(value) is not int or not 1 <= value <= 2**31 - 1:
                raise PrincipalAuthenticationError("Serialized principal policy version is invalid")
        elif name in {"authenticated_at", "expires_at"}:
            _timestamp(value, name)
        elif name != "operation":
            _identifier(value, name)
    for name, prefix in (("assertion_id", "PAS"), ("scope_grant_id", "SGR"), ("store_id", "STR")):
        if re.fullmatch(prefix + r"-[0-9A-F]{32}", principal[name]) is None:
            raise PrincipalAuthenticationError(f"Serialized principal {name} is invalid")
    if (
        PROFILE_ID_PATTERN.fullmatch(principal["profile_id"]) is None
        or MISSION_ID_PATTERN.fullmatch(principal["mission_id"]) is None
    ):
        raise PrincipalAuthenticationError("Serialized principal profile or mission is invalid")
    if (
        principal["operation"] != operation.value
        or principal["profile_id"] != intent["principal_profile_id"]
        or principal["mission_id"] != intent["mission_id"]
        or principal["operation_intent_sha256"] != compute_operation_intent_hash(operation, intent)
        or principal["authenticated_at"] != authenticated_at
        or _timestamp(principal["expires_at"], "principal.expires_at")
        <= _timestamp(authenticated_at, "authenticated_at")
    ):
        raise PrincipalAuthenticationError(
            "Serialized principal intent or authentication window does not reconcile"
        )


def _validate_source_joins(
    request: ProviderEvidenceRepositoryIngestRequest,
    receipt: ProviderEvidenceRepositoryIngestReceipt,
    lifecycle_policy: ProviderEvidenceLifecyclePolicy,
    source: dict[str, Any],
    dispatch: CollaborationExecutorDispatchEnvelope,
) -> tuple[dict[str, Any], dict[str, Any]]:
    request_document, policy = _validate_lifecycle_binding(request, lifecycle_policy)
    report = source["provider_report"]
    acknowledgement = report["provider_acknowledgement"]
    verification = request_document["evidence_verification"]
    expected = {
        "report_authentication_id": source["report_authentication_id"],
        "report_authentication_sha256": source["report_authentication_sha256"],
        "report_custody_id": report["report_custody_id"],
        "report_custody_sha256": report["report_custody_sha256"],
        "attempt_id": report["invocation_preparation"]["attempt_id"],
        "acknowledgement_id": acknowledgement["acknowledgement_id"],
        "acknowledgement_sha256": acknowledgement["acknowledgement_sha256"],
        "provider_evidence_sha256": acknowledgement["provider_evidence_sha256"],
    }
    if any(verification[key] != value for key, value in expected.items()):
        raise PrincipalAuthenticationError(
            "Evidence verification does not match the complete source projection"
        )
    dispatch_document = dispatch.to_dict()
    try:
        parsed_acknowledgement = CollaborationExecutorAcknowledgement.from_dict(acknowledgement)
        validate_collaboration_executor_acknowledgement(dispatch, parsed_acknowledgement)
    except (SunderkeyError, TypeError, ValueError) as exc:
        raise PrincipalAuthenticationError(
            "Evidence source report does not match the source dispatch"
        ) from exc
    authentication = source["acknowledgement_authentication"]
    worker = authentication["worker_attestor"]
    mission = dispatch_document["mission"]
    scope_hash = "sha256:" + hashlib.sha256(mission["scope_reference"].encode("utf-8")).hexdigest()
    if (
        worker["mission_id"] != policy["mission"]["mission_id"]
        or mission["mission_id"] != policy["mission"]["mission_id"]
        or mission["mission_sha256"] != policy["mission"]["mission_sha256"]
        or scope_hash != policy["mission"]["scope_reference_sha256"]
    ):
        raise PrincipalAuthenticationError(
            "Evidence source mission does not match the lifecycle policy"
        )
    operation = (
        PrincipalOperation.EXECUTOR_ACKNOWLEDGE_SAFETY
        if dispatch_document["operation"] in SAFETY_REDUCING_OPERATIONS
        else PrincipalOperation.EXECUTOR_ACKNOWLEDGE
    )
    acknowledgement_selection = collaboration_executor_acknowledgement_selection_sha256(
        parsed_acknowledgement
    )
    _validate_principal_document(
        worker,
        operation=operation,
        intent={
            "acknowledgement_selection_sha256": acknowledgement_selection,
            "dispatch_sha256": dispatch.dispatch_sha256,
            "mission_id": mission["mission_id"],
            "principal_profile_id": dispatch_document["worker"]["worker_principal_id"],
        },
        authenticated_at=authentication["authenticated_at"],
    )
    source_time = _timestamp(authentication["authenticated_at"], "source.authenticated_at")
    if not (
        _timestamp(dispatch_document["issued_at"], "dispatch.issued_at")
        <= _timestamp(report["invocation_preparation"]["prepared_at"], "source.prepared_at")
        <= _timestamp(acknowledgement["acknowledged_at"], "source.acknowledged_at")
        <= _timestamp(report["received_at"], "source.received_at")
        <= source_time
        <= _timestamp(verification["verified_at"], "verification.verified_at")
        <= _timestamp(request_document["requested_at"], "request.requested_at")
        <= _timestamp(receipt.to_dict()["responded_at"], "receipt.responded_at")
    ) or source_time > _timestamp(dispatch_document["expires_at"], "dispatch.expires_at"):
        raise PrincipalAuthenticationError(
            "Evidence source verification chronology does not reconcile"
        )
    return request_document, policy


def _parsed_sources(document: dict[str, Any]) -> tuple[Any, Any, Any, dict[str, Any], Any]:
    request = _rebuild(ProviderEvidenceRepositoryIngestRequest, document["ingest_request"])
    receipt = _rebuild(ProviderEvidenceRepositoryIngestReceipt, document["ingest_receipt"])
    policy = _rebuild(ProviderEvidenceLifecyclePolicy, document["lifecycle_policy"])
    dispatch = _rebuild(CollaborationExecutorDispatchEnvelope, document["source_dispatch"])
    try:
        receipt = validate_provider_evidence_repository_ingest_receipt(request, receipt)
        source = validate_authenticated_collaboration_executor_provider_report_document(
            document["source_report_authentication"]
        )
    except (SunderkeyError, TypeError, ValueError, AttributeError, KeyError) as exc:
        raise PrincipalAuthenticationError(
            "Repository receipt/source authentication is invalid"
        ) from exc
    if _canonical_json(source) != _canonical_json(document["source_report_authentication"]):
        raise PrincipalAuthenticationError("Repository source normalization changed its content")
    _validate_source_joins(request, receipt, policy, source, dispatch)
    return request, receipt, policy, source, dispatch


def validate_authenticated_provider_evidence_repository_ingest_receipt_document(
    raw: Any,
) -> dict[str, Any]:
    """Return detached unsigned content/integrity material, not verified authority."""
    _bounded_native(raw)
    _fields(
        raw,
        {
            "schema_version",
            "authentication_id",
            "authentication_sha256",
            "ingest_request",
            "ingest_receipt",
            "lifecycle_policy",
            "source_report_authentication",
            "source_dispatch",
            "repository_attestor",
            "authenticated_at",
            *_BOUNDARY,
        },
        "Repository ingest authentication",
    )
    if raw["schema_version"] != 1 or any(
        type(raw[key]) is not type(value) or raw[key] != value for key, value in _BOUNDARY.items()
    ):
        raise PrincipalAuthenticationError("Repository authentication boundary is invalid")
    document = json.loads(_canonical_json(raw))
    request, receipt, policy, source, _ = _parsed_sources(document)
    attestor = document["repository_attestor"]
    _fields(attestor, _PRINCIPAL_FIELDS, "Repository attestor")
    selection = provider_evidence_repository_ingest_receipt_selection_sha256(receipt)
    intent = {
        "ingest_receipt_selection_sha256": selection,
        "ingest_request_sha256": request.request_sha256,
        "lifecycle_policy_sha256": policy.policy_sha256,
        "mission_id": policy.to_dict()["mission"]["mission_id"],
        "principal_profile_id": attestor["profile_id"],
    }
    _validate_principal_document(
        attestor,
        operation=PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE,
        intent=intent,
        authenticated_at=document["authenticated_at"],
    )
    worker = source["acknowledgement_authentication"]["worker_attestor"]
    if any(attestor[name] != worker[name] for name in ("audience", "store_id", "mission_id")):
        raise PrincipalAuthenticationError(
            "Repository and source principal contexts do not reconcile"
        )
    authenticated_at = _timestamp(document["authenticated_at"], "authenticated_at")
    if not (
        _timestamp(receipt.to_dict()["responded_at"], "responded_at")
        <= authenticated_at
        <= _timestamp(request.to_dict()["expires_at"], "request.expires_at")
    ):
        raise PrincipalAuthenticationError("Repository authentication is outside the ingest window")
    body = {
        key: value
        for key, value in document.items()
        if key not in {"authentication_id", "authentication_sha256"}
    }
    digest = _canonical_sha256({"domain": AUTHENTICATION_DOMAIN, "authentication": body})
    if (
        _digest(document["authentication_sha256"], "authentication_sha256") != digest
        or document["authentication_id"] != "ERI-" + digest.removeprefix("sha256:")[:32].upper()
    ):
        raise PrincipalAuthenticationError("Repository authentication identity is invalid")
    return document


def _receipt_snapshot(authenticated: Any) -> dict[str, Any]:
    if type(authenticated) is not AuthenticatedProviderEvidenceRepositoryIngestReceipt:
        raise PrincipalAuthenticationError(
            "Repository authentication requires its exact wrapper family"
        )
    document = {
        "schema_version": 1,
        "ingest_request": _capture_wrapper(
            authenticated.ingest_request,
            ProviderEvidenceRepositoryIngestRequest,
            "request_id",
            "request_sha256",
        ),
        "ingest_receipt": _capture_wrapper(
            authenticated.ingest_receipt,
            ProviderEvidenceRepositoryIngestReceipt,
            "receipt_id",
            "receipt_sha256",
        ),
        "lifecycle_policy": _capture_wrapper(
            authenticated.lifecycle_policy,
            ProviderEvidenceLifecyclePolicy,
            "policy_id",
            "policy_sha256",
        ),
        "source_report_authentication": _source_snapshot(
            authenticated.source_report_authentication
        ),
        "source_dispatch": _capture_wrapper(
            authenticated.source_dispatch,
            CollaborationExecutorDispatchEnvelope,
            "dispatch_id",
            "dispatch_sha256",
        ),
        "repository_attestor": _principal_snapshot(authenticated.repository_attestor),
        "authenticated_at": authenticated.authenticated_at,
        "authentication_id": authenticated.authentication_id,
        "authentication_sha256": authenticated.authentication_sha256,
        **_BOUNDARY,
    }
    _bounded_native(document)
    if (
        not authenticated.repository_attestor._proof_is_valid()
        or type(authenticated._proof) is not bytes
        or not hmac.compare_digest(authenticated._proof, _proof(document))
    ):
        raise PrincipalAuthenticationError("Repository authentication wrapper proof is invalid")
    return document


def provider_evidence_repository_ingest_authentication_effect_payload(
    authenticated: AuthenticatedProviderEvidenceRepositoryIngestReceipt | dict[str, Any],
) -> dict[str, Any]:
    """Describe exact metadata only; do not consume assertions or confer authority."""
    document = validate_authenticated_provider_evidence_repository_ingest_receipt_document(
        authenticated if type(authenticated) is dict else _receipt_snapshot(authenticated)
    )
    request = document["ingest_request"]
    receipt = document["ingest_receipt"]
    policy = document["lifecycle_policy"]
    source = document["source_report_authentication"]
    dispatch = document["source_dispatch"]
    return {
        "authentication_id": document["authentication_id"],
        "authentication_sha256": document["authentication_sha256"],
        "ingest_request_id": request["request_id"],
        "ingest_request_sha256": request["request_sha256"],
        "ingest_receipt_id": receipt["receipt_id"],
        "ingest_receipt_sha256": receipt["receipt_sha256"],
        "lifecycle_policy_id": policy["policy_id"],
        "lifecycle_policy_sha256": policy["policy_sha256"],
        "source_report_authentication_id": source["report_authentication_id"],
        "source_report_authentication_sha256": source["report_authentication_sha256"],
        "source_dispatch_id": dispatch["dispatch_id"],
        "source_dispatch_sha256": dispatch["dispatch_sha256"],
        "mission_id": policy["mission"]["mission_id"],
        "content_address": request["content_address"],
        "evidence_size_bytes": request["evidence_verification"]["evidence_size_bytes"],
        "repository_object": dict(receipt["repository_object"]),
        "outcome": receipt["outcome"],
        "authenticated_at": document["authenticated_at"],
        "validation_status": "unsigned_content_integrity_only",
        "current_authority_status": "not_verified",
        "authority_effect": "none",
        "qualification_effect": "none",
        **_BOUNDARY,
    }


def authenticate_provider_evidence_repository_ingest_receipt(
    request: ProviderEvidenceRepositoryIngestRequest,
    receipt: ProviderEvidenceRepositoryIngestReceipt,
    lifecycle_policy: ProviderEvidenceLifecyclePolicy,
    source_report_authentication: (
        AuthenticatedCollaborationExecutorProviderReport | dict[str, Any]
    ),
    source_dispatch: CollaborationExecutorDispatchEnvelope,
    *,
    repository_assertion: PrincipalAssertion,
    verified_policy: VerifiedTrustPolicy,
    repository_scope: VerifiedScopeGrant,
    repository_principal_subject: str,
    repository_principal_profile_id: str,
    expected_audience: str,
    expected_store_id: str,
    clock: Callable[[], datetime],
) -> AuthenticatedProviderEvidenceRepositoryIngestReceipt:
    """Authenticate receipt provenance while leaving repository controls unverified."""

    source_wrapper = source_report_authentication
    sources = {
        "ingest_request": _capture_wrapper(
            request, ProviderEvidenceRepositoryIngestRequest, "request_id", "request_sha256"
        ),
        "ingest_receipt": _capture_wrapper(
            receipt, ProviderEvidenceRepositoryIngestReceipt, "receipt_id", "receipt_sha256"
        ),
        "lifecycle_policy": _capture_wrapper(
            lifecycle_policy, ProviderEvidenceLifecyclePolicy, "policy_id", "policy_sha256"
        ),
        "source_report_authentication": _source_snapshot(source_wrapper),
        "source_dispatch": _capture_wrapper(
            source_dispatch, CollaborationExecutorDispatchEnvelope, "dispatch_id", "dispatch_sha256"
        ),
    }
    if (
        type(repository_assertion) is not PrincipalAssertion
        or type(repository_assertion.operation) is not PrincipalOperation
    ):
        raise PrincipalAuthenticationError("Repository assertion requires its exact native family")
    assertion_document = repository_assertion.to_dict()
    _bounded_native(
        {
            **sources,
            "repository_assertion": assertion_document,
            "expected_identity": [
                repository_principal_subject,
                repository_principal_profile_id,
                expected_audience,
                expected_store_id,
            ],
        }
    )
    for label, value in (
        ("repository_principal_subject", repository_principal_subject),
        ("repository_principal_profile_id", repository_principal_profile_id),
        ("expected_audience", expected_audience),
        ("expected_store_id", expected_store_id),
    ):
        _identifier(value, label)
    if type(source_wrapper) is AuthenticatedCollaborationExecutorProviderReport and (
        not source_wrapper.acknowledgement_authentication._proof_is_valid()
        or not source_wrapper._proof_is_valid()
    ):
        raise PrincipalAuthenticationError("Source authentication wrapper proof is invalid")
    sources = json.loads(_canonical_json(sources))
    request, receipt, lifecycle_policy, source_report_authentication, source_dispatch = (
        _parsed_sources(sources)
    )
    repository_assertion = PrincipalAssertion.from_dict(assertion_document)
    request_document = request.to_dict()
    policy_document = lifecycle_policy.to_dict()
    worker = source_report_authentication["acknowledgement_authentication"]["worker_attestor"]
    if worker["audience"] != expected_audience or worker["store_id"] != expected_store_id:
        raise PrincipalAuthenticationError(
            "Source principal context does not match the expected repository context"
        )
    if (
        repository_assertion.subject != repository_principal_subject
        or repository_assertion.profile_id != repository_principal_profile_id
    ):
        raise PrincipalAuthenticationError(
            "Repository assertion principal does not match the expected identity"
        )

    now = _clock_value(clock)
    requested_at = parse_timestamp(
        request_document["requested_at"],
        "ingest_request.requested_at",
    )
    expires_at = parse_timestamp(
        request_document["expires_at"],
        "ingest_request.expires_at",
    )
    responded_at = parse_timestamp(
        receipt.to_dict()["responded_at"],
        "ingest_receipt.responded_at",
    )
    if not requested_at <= responded_at <= now <= expires_at:
        raise PrincipalAuthenticationError(
            "Repository receipt authentication is outside the ingest window"
        )
    assertion_issued_at = parse_timestamp(
        repository_assertion.issued_at,
        "repository_assertion.issued_at",
    )
    if assertion_issued_at < responded_at:
        raise PrincipalAuthenticationError("Repository assertion precedes the provider receipt")

    scope_document = repository_scope.grant.to_dict()
    scope_duration = parse_timestamp(
        scope_document["expires_at"],
        "repository_scope.expires_at",
    ) - parse_timestamp(
        scope_document["not_before"],
        "repository_scope.not_before",
    )
    if scope_duration.total_seconds() > policy_document["access"]["maximum_access_seconds"]:
        raise PrincipalAuthenticationError("Repository scope exceeds the lifecycle access duration")

    selection_sha256 = provider_evidence_repository_ingest_receipt_selection_sha256(receipt)
    mission_id = policy_document["mission"]["mission_id"]
    operation = PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE
    intent = {
        "ingest_receipt_selection_sha256": selection_sha256,
        "ingest_request_sha256": request.request_sha256,
        "lifecycle_policy_sha256": lifecycle_policy.policy_sha256,
        "mission_id": mission_id,
        "principal_profile_id": repository_principal_profile_id,
    }
    repository_attestor = verify_principal_assertion(
        repository_assertion,
        verified_policy,
        repository_scope,
        expected_audience=expected_audience,
        expected_store_id=expected_store_id,
        expected_mission_id=mission_id,
        expected_operation=operation,
        expected_operation_intent_sha256=compute_operation_intent_hash(
            operation,
            intent,
        ),
        clock=lambda: now,
    )
    authenticated_at = now.isoformat().replace("+00:00", "Z")
    body = _authentication_body(
        request,
        receipt,
        lifecycle_policy,
        source_report_authentication,
        source_dispatch,
        repository_attestor,
        authenticated_at,
    )
    _bounded_native(body)
    digest = _canonical_sha256({"domain": AUTHENTICATION_DOMAIN, "authentication": body})
    authentication_id = "ERI-" + digest.removeprefix("sha256:")[:32].upper()
    document = {
        **body,
        "authentication_id": authentication_id,
        "authentication_sha256": digest,
    }
    _bounded_native(document)
    return AuthenticatedProviderEvidenceRepositoryIngestReceipt(
        authentication_id=authentication_id,
        authentication_sha256=digest,
        ingest_request=request,
        ingest_receipt=receipt,
        lifecycle_policy=lifecycle_policy,
        source_report_authentication=source_report_authentication,
        source_dispatch=source_dispatch,
        repository_attestor=repository_attestor,
        authenticated_at=authenticated_at,
        _proof=_proof(document),
    )


__all__ = [
    "AuthenticatedProviderEvidenceRepositoryIngestReceipt",
    "authenticate_provider_evidence_repository_ingest_receipt",
    "provider_evidence_repository_ingest_authentication_effect_payload",
    "provider_evidence_repository_ingest_receipt_selection_sha256",
    "validate_authenticated_provider_evidence_repository_ingest_receipt_document",
]
