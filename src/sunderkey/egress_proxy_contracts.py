"""Fail-closed contracts for controlled worker egress.

The module evaluates immutable policy and observation records. It does not open
sockets, resolve names, forward requests, or claim that a proxy enforced a
decision.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = 1
NO_EFFECTS = True
_REF_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}:[A-Za-z0-9._~:/+-]{1,255}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HOST_RE = re.compile(
    r"^(?=.{1,253}\Z)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")
_METHODS = frozenset({"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"})


class EgressProxyContractError(ValueError):
    """Raised when an egress contract is invalid or unsafe."""


class EgressProtocol(StrEnum):
    HTTPS = "https"


class AdmissionDisposition(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class ObservationOutcome(StrEnum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"kind": kind, "body": body})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _ref(value: str, label: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise EgressProxyContractError(f"{label} must be a namespaced reference")
    return value


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise EgressProxyContractError(f"{label} must be a sha256 digest")
    return value


def _time(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EgressProxyContractError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise EgressProxyContractError(f"{label} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo != UTC:
        raise EgressProxyContractError(f"{label} must be UTC")
    return value


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _host(value: str) -> str:
    if not isinstance(value, str) or value != value.lower() or not _HOST_RE.fullmatch(value):
        raise EgressProxyContractError("host must be a lowercase DNS name")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise EgressProxyContractError("host must not be an IP literal")


def _path(value: str, label: str) -> str:
    if not isinstance(value, str) or not _PATH_RE.fullmatch(value):
        raise EgressProxyContractError(f"{label} must be an absolute normalized path")
    if "//" in value or "/../" in value or value.endswith("/..") or "/./" in value:
        raise EgressProxyContractError(f"{label} must not contain path traversal or empty segments")
    return value


def _exact(raw: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(raw)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise EgressProxyContractError(f"{label} fields differ: missing={missing}, extra={extra}")


def _addressed(instance: Any, id_name: str, hash_name: str) -> dict[str, Any]:
    body = instance.body()
    record_id, digest = _identity(instance.ID_PREFIX, instance.KIND, body)
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": instance.KIND,
        id_name: record_id,
        hash_name: digest,
        **body,
    }


def _verify_addressed(
    raw: Mapping[str, Any],
    instance: Any,
    id_name: str,
    hash_name: str,
) -> Any:
    if dict(raw) != instance.to_dict():
        raise EgressProxyContractError(f"{instance.KIND} content address mismatch")
    return instance


@dataclass(frozen=True, slots=True)
class EndpointRule:
    rule_ref: str
    host: str
    port: int
    allowed_methods: tuple[str, ...]
    allowed_path_prefixes: tuple[str, ...]
    allowed_ip_networks: tuple[str, ...]
    tls_spki_sha256: tuple[str, ...]
    max_request_bytes: int
    max_response_bytes: int

    def __post_init__(self) -> None:
        _ref(self.rule_ref, "rule_ref")
        _host(self.host)
        if (
            not isinstance(self.port, int)
            or isinstance(self.port, bool)
            or not 1 <= self.port <= 65535
        ):
            raise EgressProxyContractError("port must be in 1..65535")
        methods = tuple(sorted(set(self.allowed_methods)))
        if not methods or any(method not in _METHODS for method in methods):
            raise EgressProxyContractError("allowed_methods contains an unsupported method")
        object.__setattr__(self, "allowed_methods", methods)
        prefixes = tuple(sorted(set(self.allowed_path_prefixes)))
        if not prefixes:
            raise EgressProxyContractError("allowed_path_prefixes must not be empty")
        for prefix in prefixes:
            _path(prefix, "allowed_path_prefix")
        object.__setattr__(self, "allowed_path_prefixes", prefixes)
        networks: list[str] = []
        for value in self.allowed_ip_networks:
            try:
                network = ipaddress.ip_network(value, strict=True)
            except ValueError as exc:
                raise EgressProxyContractError("allowed_ip_networks contains invalid CIDR") from exc
            networks.append(str(network))
        normalized_networks = tuple(sorted(set(networks)))
        if not normalized_networks:
            raise EgressProxyContractError("allowed_ip_networks must not be empty")
        object.__setattr__(self, "allowed_ip_networks", normalized_networks)
        pins = tuple(sorted(set(self.tls_spki_sha256)))
        if not pins:
            raise EgressProxyContractError("tls_spki_sha256 must not be empty")
        for pin in pins:
            _digest(pin, "tls_spki_sha256")
        object.__setattr__(self, "tls_spki_sha256", pins)
        for label, value in (
            ("max_request_bytes", self.max_request_bytes),
            ("max_response_bytes", self.max_response_bytes),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value <= 1_000_000_000
            ):
                raise EgressProxyContractError(f"{label} must be in 0..1000000000")

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_ip_networks": list(self.allowed_ip_networks),
            "allowed_methods": list(self.allowed_methods),
            "allowed_path_prefixes": list(self.allowed_path_prefixes),
            "host": self.host,
            "max_request_bytes": self.max_request_bytes,
            "max_response_bytes": self.max_response_bytes,
            "port": self.port,
            "rule_ref": self.rule_ref,
            "tls_spki_sha256": list(self.tls_spki_sha256),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> EndpointRule:
        fields = {
            "allowed_ip_networks",
            "allowed_methods",
            "allowed_path_prefixes",
            "host",
            "max_request_bytes",
            "max_response_bytes",
            "port",
            "rule_ref",
            "tls_spki_sha256",
        }
        _exact(raw, fields, "endpoint_rule")
        return cls(
            rule_ref=raw["rule_ref"],
            host=raw["host"],
            port=raw["port"],
            allowed_methods=tuple(raw["allowed_methods"]),
            allowed_path_prefixes=tuple(raw["allowed_path_prefixes"]),
            allowed_ip_networks=tuple(raw["allowed_ip_networks"]),
            tls_spki_sha256=tuple(raw["tls_spki_sha256"]),
            max_request_bytes=raw["max_request_bytes"],
            max_response_bytes=raw["max_response_bytes"],
        )


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    tenant_ref: str
    mission_ref: str
    scope_ref: str
    worker_ref: str
    policy_version: int
    valid_from: str
    valid_until: str
    maximum_resolution_age_seconds: int
    endpoint_rules: tuple[EndpointRule, ...]
    default_disposition: AdmissionDisposition = AdmissionDisposition.DENY
    redirects_allowed: bool = False

    KIND = "egress_policy"
    ID_PREFIX = "EGP"

    def __post_init__(self) -> None:
        for label in ("tenant_ref", "mission_ref", "scope_ref", "worker_ref"):
            _ref(getattr(self, label), label)
        if (
            not isinstance(self.policy_version, int)
            or isinstance(self.policy_version, bool)
            or self.policy_version < 1
        ):
            raise EgressProxyContractError("policy_version must be a positive integer")
        _time(self.valid_from, "valid_from")
        _time(self.valid_until, "valid_until")
        if _instant(self.valid_until) <= _instant(self.valid_from):
            raise EgressProxyContractError("valid_until must be later than valid_from")
        if (
            not isinstance(self.maximum_resolution_age_seconds, int)
            or not 1 <= self.maximum_resolution_age_seconds <= 3600
        ):
            raise EgressProxyContractError("maximum_resolution_age_seconds must be in 1..3600")
        rules = tuple(self.endpoint_rules)
        if not rules:
            raise EgressProxyContractError("endpoint_rules must not be empty")
        keys = [(rule.host, rule.port) for rule in rules]
        if len(keys) != len(set(keys)):
            raise EgressProxyContractError("endpoint_rules must have unique host and port pairs")
        if len({rule.rule_ref for rule in rules}) != len(rules):
            raise EgressProxyContractError("endpoint rule references must be unique")
        object.__setattr__(
            self, "endpoint_rules", tuple(sorted(rules, key=lambda item: item.rule_ref))
        )
        object.__setattr__(
            self, "default_disposition", AdmissionDisposition(self.default_disposition)
        )
        if self.default_disposition is not AdmissionDisposition.DENY:
            raise EgressProxyContractError("default_disposition must be deny")
        if self.redirects_allowed:
            raise EgressProxyContractError("redirects_allowed must be false")

    def body(self) -> dict[str, Any]:
        return {
            "default_disposition": self.default_disposition.value,
            "endpoint_rules": [rule.to_dict() for rule in self.endpoint_rules],
            "maximum_resolution_age_seconds": self.maximum_resolution_age_seconds,
            "mission_ref": self.mission_ref,
            "policy_version": self.policy_version,
            "redirects_allowed": self.redirects_allowed,
            "scope_ref": self.scope_ref,
            "tenant_ref": self.tenant_ref,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "worker_ref": self.worker_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "policy_id", "policy_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> EgressPolicy:
        fields = {
            "default_disposition",
            "endpoint_rules",
            "kind",
            "maximum_resolution_age_seconds",
            "mission_ref",
            "policy_id",
            "policy_sha256",
            "policy_version",
            "redirects_allowed",
            "schema_version",
            "scope_ref",
            "tenant_ref",
            "valid_from",
            "valid_until",
            "worker_ref",
        }
        _exact(raw, fields, cls.KIND)
        if raw["schema_version"] != SCHEMA_VERSION or raw["kind"] != cls.KIND:
            raise EgressProxyContractError("egress policy metadata is invalid")
        instance = cls(
            tenant_ref=raw["tenant_ref"],
            mission_ref=raw["mission_ref"],
            scope_ref=raw["scope_ref"],
            worker_ref=raw["worker_ref"],
            policy_version=raw["policy_version"],
            valid_from=raw["valid_from"],
            valid_until=raw["valid_until"],
            maximum_resolution_age_seconds=raw["maximum_resolution_age_seconds"],
            endpoint_rules=tuple(EndpointRule.from_dict(item) for item in raw["endpoint_rules"]),
            default_disposition=raw["default_disposition"],
            redirects_allowed=raw["redirects_allowed"],
        )
        return _verify_addressed(raw, instance, "policy_id", "policy_sha256")


@dataclass(frozen=True, slots=True)
class ResolutionAttestation:
    tenant_ref: str
    mission_ref: str
    worker_ref: str
    host: str
    resolver_ref: str
    resolved_addresses: tuple[str, ...]
    observed_at: str
    expires_at: str
    collector_signature_ref: str
    collector_signature_sha256: str

    KIND = "resolution_attestation"
    ID_PREFIX = "ERA"

    def __post_init__(self) -> None:
        for label in (
            "tenant_ref",
            "mission_ref",
            "worker_ref",
            "resolver_ref",
            "collector_signature_ref",
        ):
            _ref(getattr(self, label), label)
        _host(self.host)
        addresses: list[str] = []
        for value in self.resolved_addresses:
            try:
                addresses.append(str(ipaddress.ip_address(value)))
            except ValueError as exc:
                raise EgressProxyContractError(
                    "resolved_addresses contains an invalid address"
                ) from exc
        normalized = tuple(sorted(set(addresses)))
        if not normalized:
            raise EgressProxyContractError("resolved_addresses must not be empty")
        object.__setattr__(self, "resolved_addresses", normalized)
        _time(self.observed_at, "observed_at")
        _time(self.expires_at, "expires_at")
        if _instant(self.expires_at) <= _instant(self.observed_at):
            raise EgressProxyContractError("expires_at must be later than observed_at")
        _digest(self.collector_signature_sha256, "collector_signature_sha256")

    def body(self) -> dict[str, Any]:
        return {
            "collector_signature_ref": self.collector_signature_ref,
            "collector_signature_sha256": self.collector_signature_sha256,
            "expires_at": self.expires_at,
            "host": self.host,
            "mission_ref": self.mission_ref,
            "observed_at": self.observed_at,
            "resolved_addresses": list(self.resolved_addresses),
            "resolver_ref": self.resolver_ref,
            "tenant_ref": self.tenant_ref,
            "worker_ref": self.worker_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "attestation_id", "attestation_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ResolutionAttestation:
        fields = {
            "attestation_id",
            "attestation_sha256",
            "collector_signature_ref",
            "collector_signature_sha256",
            "expires_at",
            "host",
            "kind",
            "mission_ref",
            "observed_at",
            "resolved_addresses",
            "resolver_ref",
            "schema_version",
            "tenant_ref",
            "worker_ref",
        }
        _exact(raw, fields, cls.KIND)
        if raw["schema_version"] != SCHEMA_VERSION or raw["kind"] != cls.KIND:
            raise EgressProxyContractError("resolution attestation metadata is invalid")
        instance = cls(
            tenant_ref=raw["tenant_ref"],
            mission_ref=raw["mission_ref"],
            worker_ref=raw["worker_ref"],
            host=raw["host"],
            resolver_ref=raw["resolver_ref"],
            resolved_addresses=tuple(raw["resolved_addresses"]),
            observed_at=raw["observed_at"],
            expires_at=raw["expires_at"],
            collector_signature_ref=raw["collector_signature_ref"],
            collector_signature_sha256=raw["collector_signature_sha256"],
        )
        return _verify_addressed(raw, instance, "attestation_id", "attestation_sha256")


@dataclass(frozen=True, slots=True)
class EgressRequest:
    tenant_ref: str
    mission_ref: str
    scope_ref: str
    worker_ref: str
    operation_ref: str
    protocol: EgressProtocol
    host: str
    port: int
    method: str
    path: str
    request_bytes: int
    body_sha256: str
    credential_lease_ref: str | None
    follow_redirects: bool
    requested_at: str
    policy_id: str
    policy_sha256: str
    resolution_attestation_id: str
    resolution_attestation_sha256: str

    KIND = "egress_request"
    ID_PREFIX = "EGR"

    def __post_init__(self) -> None:
        for label in ("tenant_ref", "mission_ref", "scope_ref", "worker_ref", "operation_ref"):
            _ref(getattr(self, label), label)
        object.__setattr__(self, "protocol", EgressProtocol(self.protocol))
        _host(self.host)
        if (
            not isinstance(self.port, int)
            or isinstance(self.port, bool)
            or not 1 <= self.port <= 65535
        ):
            raise EgressProxyContractError("port must be in 1..65535")
        if self.method not in _METHODS:
            raise EgressProxyContractError("method is unsupported")
        _path(self.path, "path")
        if (
            not isinstance(self.request_bytes, int)
            or isinstance(self.request_bytes, bool)
            or not 0 <= self.request_bytes <= 1_000_000_000
        ):
            raise EgressProxyContractError("request_bytes must be in 0..1000000000")
        _digest(self.body_sha256, "body_sha256")
        if self.credential_lease_ref is not None:
            _ref(self.credential_lease_ref, "credential_lease_ref")
        _time(self.requested_at, "requested_at")
        if not isinstance(self.policy_id, str) or not self.policy_id.startswith("EGP-"):
            raise EgressProxyContractError("policy_id is invalid")
        _digest(self.policy_sha256, "policy_sha256")
        if not isinstance(
            self.resolution_attestation_id, str
        ) or not self.resolution_attestation_id.startswith("ERA-"):
            raise EgressProxyContractError("resolution_attestation_id is invalid")
        _digest(self.resolution_attestation_sha256, "resolution_attestation_sha256")

    def body(self) -> dict[str, Any]:
        return {
            "body_sha256": self.body_sha256,
            "credential_lease_ref": self.credential_lease_ref,
            "follow_redirects": self.follow_redirects,
            "host": self.host,
            "method": self.method,
            "mission_ref": self.mission_ref,
            "operation_ref": self.operation_ref,
            "path": self.path,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "port": self.port,
            "protocol": self.protocol.value,
            "request_bytes": self.request_bytes,
            "requested_at": self.requested_at,
            "resolution_attestation_id": self.resolution_attestation_id,
            "resolution_attestation_sha256": self.resolution_attestation_sha256,
            "scope_ref": self.scope_ref,
            "tenant_ref": self.tenant_ref,
            "worker_ref": self.worker_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "request_id", "request_sha256")


@dataclass(frozen=True, slots=True)
class EgressAdmissionDecision:
    request_id: str
    request_sha256: str
    policy_id: str
    policy_sha256: str
    resolution_attestation_id: str
    resolution_attestation_sha256: str
    disposition: AdmissionDisposition
    matched_rule_ref: str | None
    blocker_codes: tuple[str, ...]
    evaluated_at: str

    KIND = "egress_admission_decision"
    ID_PREFIX = "EAD"

    def __post_init__(self) -> None:
        for label, prefix in (
            ("request_id", "EGR-"),
            ("policy_id", "EGP-"),
            ("resolution_attestation_id", "ERA-"),
        ):
            if not getattr(self, label).startswith(prefix):
                raise EgressProxyContractError(f"{label} is invalid")
        for label in ("request_sha256", "policy_sha256", "resolution_attestation_sha256"):
            _digest(getattr(self, label), label)
        object.__setattr__(self, "disposition", AdmissionDisposition(self.disposition))
        if self.matched_rule_ref is not None:
            _ref(self.matched_rule_ref, "matched_rule_ref")
        blockers = tuple(sorted(set(self.blocker_codes)))
        if any(not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", item) for item in blockers):
            raise EgressProxyContractError("blocker_codes contains an invalid code")
        object.__setattr__(self, "blocker_codes", blockers)
        if self.disposition is AdmissionDisposition.ALLOW and (
            blockers or self.matched_rule_ref is None
        ):
            raise EgressProxyContractError("allow decisions require a rule and no blockers")
        if self.disposition is AdmissionDisposition.DENY and not blockers:
            raise EgressProxyContractError("deny decisions require blockers")
        _time(self.evaluated_at, "evaluated_at")

    def body(self) -> dict[str, Any]:
        return {
            "blocker_codes": list(self.blocker_codes),
            "disposition": self.disposition.value,
            "evaluated_at": self.evaluated_at,
            "matched_rule_ref": self.matched_rule_ref,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "resolution_attestation_id": self.resolution_attestation_id,
            "resolution_attestation_sha256": self.resolution_attestation_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "decision_id", "decision_sha256")


def evaluate_egress_request(
    policy: EgressPolicy,
    attestation: ResolutionAttestation,
    request: EgressRequest,
    *,
    evaluated_at: str,
) -> EgressAdmissionDecision:
    """Evaluate one request without performing network activity."""

    _time(evaluated_at, "evaluated_at")
    policy_doc = policy.to_dict()
    attestation_doc = attestation.to_dict()
    request_doc = request.to_dict()
    blockers: set[str] = set()
    if (request.policy_id, request.policy_sha256) != (
        policy_doc["policy_id"],
        policy_doc["policy_sha256"],
    ):
        blockers.add("policy_binding_mismatch")
    if (request.resolution_attestation_id, request.resolution_attestation_sha256) != (
        attestation_doc["attestation_id"],
        attestation_doc["attestation_sha256"],
    ):
        blockers.add("resolution_binding_mismatch")
    policy_context = (policy.tenant_ref, policy.mission_ref, policy.scope_ref, policy.worker_ref)
    request_context = (
        request.tenant_ref,
        request.mission_ref,
        request.scope_ref,
        request.worker_ref,
    )
    if request_context != policy_context:
        blockers.add("policy_context_mismatch")
    if (attestation.tenant_ref, attestation.mission_ref, attestation.worker_ref) != (
        request.tenant_ref,
        request.mission_ref,
        request.worker_ref,
    ):
        blockers.add("resolution_context_mismatch")
    now = _instant(evaluated_at)
    if now < _instant(policy.valid_from) or now >= _instant(policy.valid_until):
        blockers.add("policy_not_active")
    if now < _instant(attestation.observed_at) or now >= _instant(attestation.expires_at):
        blockers.add("resolution_not_active")
    if (
        now - _instant(attestation.observed_at)
    ).total_seconds() > policy.maximum_resolution_age_seconds:
        blockers.add("resolution_too_old")
    if attestation.host != request.host:
        blockers.add("resolution_host_mismatch")
    if request.follow_redirects:
        blockers.add("redirect_following_prohibited")
    matched = next(
        (
            rule
            for rule in policy.endpoint_rules
            if (rule.host, rule.port) == (request.host, request.port)
        ),
        None,
    )
    if matched is None:
        blockers.add("endpoint_not_allowed")
    else:
        if request.method not in matched.allowed_methods:
            blockers.add("method_not_allowed")
        if not any(
            request.path == prefix
            or request.path.startswith(prefix if prefix.endswith("/") else prefix + "/")
            for prefix in matched.allowed_path_prefixes
        ):
            blockers.add("path_not_allowed")
        if request.request_bytes > matched.max_request_bytes:
            blockers.add("request_size_exceeded")
        networks = tuple(ipaddress.ip_network(value) for value in matched.allowed_ip_networks)
        for address in attestation.resolved_addresses:
            parsed = ipaddress.ip_address(address)
            if not any(parsed in network for network in networks):
                blockers.add("resolved_address_not_allowed")
                break
    disposition = AdmissionDisposition.DENY if blockers else AdmissionDisposition.ALLOW
    return EgressAdmissionDecision(
        request_id=request_doc["request_id"],
        request_sha256=request_doc["request_sha256"],
        policy_id=policy_doc["policy_id"],
        policy_sha256=policy_doc["policy_sha256"],
        resolution_attestation_id=attestation_doc["attestation_id"],
        resolution_attestation_sha256=attestation_doc["attestation_sha256"],
        disposition=disposition,
        matched_rule_ref=matched.rule_ref if matched is not None else None,
        blocker_codes=tuple(sorted(blockers)),
        evaluated_at=evaluated_at,
    )


@dataclass(frozen=True, slots=True)
class EgressEnforcementObservation:
    decision_id: str
    decision_sha256: str
    proxy_instance_ref: str
    proxy_version: str
    observed_host: str
    observed_port: int
    resolved_address: str
    tls_spki_sha256: str
    response_bytes: int
    outcome: ObservationOutcome
    redirect_blocked: bool
    observed_at: str
    evidence_refs: tuple[str, ...]

    KIND = "egress_enforcement_observation"
    ID_PREFIX = "EEO"

    def __post_init__(self) -> None:
        if not self.decision_id.startswith("EAD-"):
            raise EgressProxyContractError("decision_id is invalid")
        _digest(self.decision_sha256, "decision_sha256")
        _ref(self.proxy_instance_ref, "proxy_instance_ref")
        if not isinstance(self.proxy_version, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", self.proxy_version
        ):
            raise EgressProxyContractError("proxy_version is invalid")
        _host(self.observed_host)
        if not isinstance(self.observed_port, int) or not 1 <= self.observed_port <= 65535:
            raise EgressProxyContractError("observed_port is invalid")
        try:
            object.__setattr__(
                self, "resolved_address", str(ipaddress.ip_address(self.resolved_address))
            )
        except ValueError as exc:
            raise EgressProxyContractError("resolved_address is invalid") from exc
        _digest(self.tls_spki_sha256, "tls_spki_sha256")
        if (
            not isinstance(self.response_bytes, int)
            or isinstance(self.response_bytes, bool)
            or not 0 <= self.response_bytes <= 1_000_000_000
        ):
            raise EgressProxyContractError("response_bytes must be in 0..1000000000")
        object.__setattr__(self, "outcome", ObservationOutcome(self.outcome))
        _time(self.observed_at, "observed_at")
        refs = tuple(sorted(set(self.evidence_refs)))
        if not refs:
            raise EgressProxyContractError("evidence_refs must not be empty")
        for value in refs:
            _ref(value, "evidence_ref")
        object.__setattr__(self, "evidence_refs", refs)

    def body(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "decision_sha256": self.decision_sha256,
            "evidence_refs": list(self.evidence_refs),
            "observed_at": self.observed_at,
            "observed_host": self.observed_host,
            "observed_port": self.observed_port,
            "outcome": self.outcome.value,
            "proxy_instance_ref": self.proxy_instance_ref,
            "proxy_version": self.proxy_version,
            "redirect_blocked": self.redirect_blocked,
            "resolved_address": self.resolved_address,
            "response_bytes": self.response_bytes,
            "tls_spki_sha256": self.tls_spki_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "observation_id", "observation_sha256")


def validate_enforcement_observation(
    policy: EgressPolicy,
    request: EgressRequest,
    decision: EgressAdmissionDecision,
    observation: EgressEnforcementObservation,
) -> tuple[str, ...]:
    """Return fail-closed evidence blockers for one proxy observation."""

    blockers: set[str] = set()
    policy_doc = policy.to_dict()
    request_doc = request.to_dict()
    decision_doc = decision.to_dict()
    if (decision.request_id, decision.request_sha256) != (
        request_doc["request_id"],
        request_doc["request_sha256"],
    ):
        blockers.add("request_binding_mismatch")
    policy_binding = (policy_doc["policy_id"], policy_doc["policy_sha256"])
    if (
        (decision.policy_id, decision.policy_sha256) != policy_binding
        or (request.policy_id, request.policy_sha256) != policy_binding
    ):
        blockers.add("policy_binding_mismatch")
    if (
        decision.resolution_attestation_id,
        decision.resolution_attestation_sha256,
    ) != (
        request.resolution_attestation_id,
        request.resolution_attestation_sha256,
    ):
        blockers.add("resolution_binding_mismatch")
    if (observation.decision_id, observation.decision_sha256) != (
        decision_doc["decision_id"],
        decision_doc["decision_sha256"],
    ):
        blockers.add("decision_binding_mismatch")
    if decision.disposition is not AdmissionDisposition.ALLOW:
        blockers.add("request_not_admitted")
    if (observation.observed_host, observation.observed_port) != (request.host, request.port):
        blockers.add("observed_endpoint_mismatch")
    rule = next(
        (item for item in policy.endpoint_rules if item.rule_ref == decision.matched_rule_ref), None
    )
    if rule is None:
        blockers.add("matched_rule_missing")
    else:
        address = ipaddress.ip_address(observation.resolved_address)
        if not any(address in ipaddress.ip_network(value) for value in rule.allowed_ip_networks):
            blockers.add("observed_address_not_allowed")
        if observation.tls_spki_sha256 not in rule.tls_spki_sha256:
            blockers.add("tls_pin_mismatch")
        if observation.response_bytes > rule.max_response_bytes:
            blockers.add("response_size_exceeded")
    if not observation.redirect_blocked:
        blockers.add("redirect_block_not_observed")
    if observation.outcome is not ObservationOutcome.COMPLETED:
        blockers.add("egress_not_completed")
    return tuple(sorted(blockers))


def parse_contract(raw: Mapping[str, Any] | str) -> EgressPolicy | ResolutionAttestation:
    document = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(document, Mapping):
        raise EgressProxyContractError("contract must be an object")
    kind = document.get("kind")
    if kind == EgressPolicy.KIND:
        return EgressPolicy.from_dict(document)
    if kind == ResolutionAttestation.KIND:
        return ResolutionAttestation.from_dict(document)
    raise EgressProxyContractError("unsupported egress contract kind")


__all__ = [
    "AdmissionDisposition",
    "EgressAdmissionDecision",
    "EgressEnforcementObservation",
    "EgressPolicy",
    "EgressProtocol",
    "EgressProxyContractError",
    "EgressRequest",
    "EndpointRule",
    "NO_EFFECTS",
    "ObservationOutcome",
    "ResolutionAttestation",
    "canonical_json",
    "canonical_sha256",
    "evaluate_egress_request",
    "parse_contract",
    "validate_enforcement_observation",
]
