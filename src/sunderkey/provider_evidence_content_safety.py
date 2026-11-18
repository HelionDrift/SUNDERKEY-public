"""Synthetic passive prefix observations and supplied derivative provenance.

No evidence parser, classifier, renderer, transformer or runtime adapter is
provided. Unsigned reports bind supplied bytes and declared source contracts,
not authenticated custody or a content-safety verdict.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .collaboration_executor_provider_evidence import MAXIMUM_EVIDENCE_BYTES
from .errors import SunderkeyError
from .provider_evidence_lifecycle import ProviderEvidenceLifecyclePolicy
from .provider_evidence_repository import (
    MAXIMUM_INGEST_WINDOW_SECONDS,
    ProviderEvidenceRepositoryIngestRequest,
    validate_provider_evidence_repository_ingest_bytes,
)
from .provider_evidence_repository_conformance import (
    MAXIMUM_DOCUMENT_BYTES,
    _bounded_json,
    _load,
    _timestamp,
)

ENVIRONMENT_CLASS = "reference_simulation_nonqualifying"
SCHEMA_VERSION = 1
PREFIX_OBSERVATION_DOMAIN = "sunderkey.provider-evidence-content-prefix-observation.v1"
DERIVATIVE_PROVENANCE_DOMAIN = "sunderkey.provider-evidence-derivative-provenance.v1"
# Named byte features, not MIME declarations or a complete format recognizer.
PREFIX_FEATURES = MappingProxyType(
    {
        "prefix:angle-open": b"<",
        "prefix:doctype-open": b"<!DOCTYPE",
        "prefix:elf-marker": b"\x7fELF",
        "prefix:gzip-marker": b"\x1f\x8b",
        "prefix:jpeg-marker": b"\xff\xd8\xff",
        "prefix:pdf-marker": b"%PDF-",
        "prefix:png-marker": b"\x89PNG\r\n\x1a\n",
        "prefix:xml-declaration-open": b"<?xml",
        "prefix:zip-empty-marker": b"PK\x05\x06",
        "prefix:zip-local-marker": b"PK\x03\x04",
        "prefix:zip-stream-marker": b"PK\x07\x08",
    }
)
MAXIMUM_PREFIX_BYTES = max(map(len, PREFIX_FEATURES.values()))
EFFECTS = MappingProxyType(
    {
        name: "none"
        for name in (
            "activation",
            "classification",
            "content_parsing",
            "execution",
            "network",
            "qualification",
            "quarantine_release",
            "redaction",
            "rendering",
            "storage",
            "target_authority",
            "transformation",
        )
    }
)
_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
_TRANSFORMATION = re.compile(r"transformationref:[A-Za-z0-9][A-Za-z0-9._:-]{0,95}")
_INTEGER_FIELDS = frozenset(
    {
        "schema_version",
        "policy_version",
        "evidence_size_bytes",
        "retention_seconds",
        "deletion_deadline_seconds",
        "maximum_access_seconds",
        "minimum_replica_count",
    }
)
_BOUNDARY = {
    "authentication_status": "unsigned_reference_metadata",
    "content_safety_status": "not_assessed",
    "lifecycle_status": "prepared_policy_bound_not_activated",
    "quarantine_status": "not_verified_or_released",
}


class ProviderEvidenceContentSafetyError(SunderkeyError):
    """Invalid synthetic content observation or derivative provenance input."""


def _error(label: str) -> ProviderEvidenceContentSafetyError:
    return ProviderEvidenceContentSafetyError(label)


def _canonical(value: Any) -> str:
    # The existing pure visitor charges escaped strings and repeated subtrees
    # before json.dumps, with 64 KiB, depth 16 and 4096-node limits.
    try:
        return _bounded_json(value)
    except (SunderkeyError, ValueError, TypeError, RecursionError) as exc:
        raise _error("Content metadata must be bounded native JSON") from exc


def _document(text: Any) -> dict[str, Any]:
    try:
        return _load(text)
    except (SunderkeyError, ValueError, TypeError, RecursionError) as exc:
        raise _error("Content metadata must be bounded strict JSON") from exc


def _fields(raw: Any, fields: set[str], label: str) -> None:
    if type(raw) is not dict or set(raw) != fields:
        raise _error(f"{label} fields are invalid")


def _digest(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise _error("Content digest must be a native canonical SHA-256")
    return value


def _identifier(value: Any) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise _error("Content reference must be a native bounded identifier")
    return value


def _size(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= MAXIMUM_EVIDENCE_BYTES:
        raise _error("Content size must be a bounded native integer")
    return value


def _bytes(value: Any) -> bytes:
    if type(value) is not bytes or not 1 <= len(value) <= MAXIMUM_EVIDENCE_BYTES:
        raise _error("Content requires bounded native bytes")
    return value


def _time(value: Any):
    try:
        return _timestamp(value)
    except (SunderkeyError, TypeError, ValueError) as exc:
        raise _error("Content source timestamp must be canonical UTC") from exc


def _environment(value: Any) -> None:
    if type(value) is not str or value != ENVIRONMENT_CLASS:
        raise _error("Only explicit reference simulation is supported")


def _wrapper_metadata(
    wrapper: Any, family: type, id_field: str, hash_field: str
) -> tuple[str, str, str]:
    if type(wrapper) is not family:
        raise _error("Content metadata requires its exact wrapper family")
    try:
        identifier = getattr(wrapper, id_field)
        digest = getattr(wrapper, hash_field)
        document = wrapper.document_json
    except AttributeError as exc:
        raise _error("Content wrapper metadata is incomplete") from exc
    _identifier(identifier)
    _digest(digest)
    if type(document) is not str:
        raise _error("Content wrapper document must be a native string")
    return identifier, digest, document


def _capture(wrapper: Any, family: type, id_field: str, hash_field: str) -> dict[str, Any]:
    identifier, digest, document = _wrapper_metadata(wrapper, family, id_field, hash_field)
    raw = _document(document)
    if (
        raw.get(id_field) != identifier
        or raw.get(hash_field) != digest
        or _canonical(raw) != document
    ):
        raise _error("Content source wrapper metadata is inconsistent")

    def integers(value: Any) -> None:
        if type(value) is dict:
            for key, item in value.items():
                if key in _INTEGER_FIELDS and type(item) is not int:
                    raise _error("Content source counters require native integers")
                integers(item)
        elif type(value) is list:
            for item in value:
                integers(item)

    integers(raw)
    return raw


def _sources(request: Any, policy: Any, evidence: bytes) -> dict[str, Any]:
    request_raw = _capture(
        request, ProviderEvidenceRepositoryIngestRequest, "request_id", "request_sha256"
    )
    policy_raw = _capture(policy, ProviderEvidenceLifecyclePolicy, "policy_id", "policy_sha256")
    try:
        request = ProviderEvidenceRepositoryIngestRequest.from_dict(request_raw)
        policy = ProviderEvidenceLifecyclePolicy.from_dict(policy_raw)
        if _canonical(request.to_dict()) != _canonical(request_raw) or _canonical(
            policy.to_dict()
        ) != _canonical(policy_raw):
            raise _error("Content source normalization changed its document")
        validate_provider_evidence_repository_ingest_bytes(request, evidence)
    except (SunderkeyError, TypeError, ValueError, AttributeError, KeyError) as exc:
        raise _error("Content bytes or source contract do not reproduce") from exc
    expected_bindings = {
        "retention_policy_id": policy.policy_id,
        "retention_policy_sha256": policy.policy_sha256,
        "residency_policy_id": policy_raw["residency"]["policy_id"],
        "residency_policy_sha256": policy_raw["residency"]["policy_sha256"],
        "encryption_profile_id": policy_raw["encryption"]["profile_id"],
        "encryption_profile_sha256": policy_raw["encryption"]["profile_sha256"],
        "access_policy_id": policy_raw["access"]["policy_id"],
        "access_policy_sha256": policy_raw["access"]["policy_sha256"],
    }
    if (
        _canonical(request_raw["lifecycle_bindings"]) != _canonical(expected_bindings)
        or _canonical(request_raw["custody_decision"]) != _canonical(policy_raw["custody_decision"])
        or _time(policy_raw["created_at"]) > _time(request_raw["requested_at"])
    ):
        raise _error("Content request and lifecycle policy binding differ")
    verification = request_raw["evidence_verification"]
    return {
        "ingest_request": {
            key: request_raw[key]
            for key in ("request_id", "request_sha256", "requested_at", "expires_at")
        },
        "lifecycle_policy": {
            key: policy_raw[key]
            for key in (
                "policy_id",
                "policy_sha256",
                "policy_version",
                "created_at",
                "policy_status",
            )
        },
        "custody_decision": dict(policy_raw["custody_decision"]),
        "mission": dict(policy_raw["mission"]),
        "evidence": {
            "verification_id": verification["verification_id"],
            "verification_sha256": verification["verification_sha256"],
            "content_address": request_raw["content_address"],
            "evidence_size_bytes": len(evidence),
            "verified_at": verification["verified_at"],
        },
    }


def _validate_source(source: Any) -> None:
    _fields(
        source,
        {"ingest_request", "lifecycle_policy", "custody_decision", "mission", "evidence"},
        "Source",
    )
    shapes = {
        "ingest_request": {"request_id", "request_sha256", "requested_at", "expires_at"},
        "lifecycle_policy": {
            "policy_id",
            "policy_sha256",
            "policy_version",
            "created_at",
            "policy_status",
        },
        "custody_decision": {"record_id", "record_sha256"},
        "mission": {"mission_id", "mission_sha256", "scope_reference_sha256"},
        "evidence": {
            "verification_id",
            "verification_sha256",
            "content_address",
            "evidence_size_bytes",
            "verified_at",
        },
    }
    identities = {
        "request_id": "EIR",
        "policy_id": "ELP",
        "record_id": "ECR",
        "verification_id": "EPV",
    }
    for name, fields in shapes.items():
        section = source[name]
        _fields(section, fields, name)
        for key, value in section.items():
            if key.endswith("sha256") or key == "content_address":
                _digest(value)
            elif key in identities:
                if (
                    type(value) is not str
                    or re.fullmatch(identities[key] + r"-[0-9A-F]{32}", value) is None
                ):
                    raise _error("Content source identity is invalid")
                digest = _digest(section[key.removesuffix("_id") + "_sha256"])
                if value != identities[key] + "-" + digest[7:39].upper():
                    raise _error("Content source identity and digest disagree")
            elif key == "mission_id":
                _identifier(value)
    request, policy, evidence = (
        source["ingest_request"],
        source["lifecycle_policy"],
        source["evidence"],
    )
    if (
        type(policy["policy_version"]) is not int
        or not 1 <= policy["policy_version"] <= 2**31 - 1
        or policy["policy_status"] != "prepared_not_activated"
    ):
        raise _error("Content lifecycle policy must remain prepared")
    _size(evidence["evidence_size_bytes"])
    if not (
        _time(policy["created_at"]) <= _time(request["requested_at"])
        and _time(evidence["verified_at"])
        <= _time(request["requested_at"])
        < _time(request["expires_at"])
    ):
        raise _error("Content source chronology is invalid")
    if (
        _time(request["expires_at"]) - _time(request["requested_at"])
    ).total_seconds() > MAXIMUM_INGEST_WINDOW_SECONDS:
        raise _error("Content source ingest window is invalid")


def _provenance_source(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "ingest_request_id": source["ingest_request"]["request_id"],
        "ingest_request_sha256": source["ingest_request"]["request_sha256"],
        "lifecycle_policy_id": source["lifecycle_policy"]["policy_id"],
        "lifecycle_policy_sha256": source["lifecycle_policy"]["policy_sha256"],
        "mission": dict(source["mission"]),
        "content_address": source["evidence"]["content_address"],
        "evidence_size_bytes": source["evidence"]["evidence_size_bytes"],
    }


def _provenance(raw: Any, source: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(_canonical(raw))
    _fields(value, {"source", "derivative", "transformation"}, "Provenance")
    if _canonical(value["source"]) != _canonical(_provenance_source(source)):
        raise _error("Derivative provenance is not bound to the exact source")
    _fields(value["derivative"], {"content_address", "evidence_size_bytes"}, "Derivative")
    _digest(value["derivative"]["content_address"])
    _size(value["derivative"]["evidence_size_bytes"])
    if value["derivative"]["content_address"] == source["evidence"]["content_address"]:
        raise _error("Derivative and source require distinct content addresses")
    transformation = value["transformation"]
    _fields(
        transformation,
        {"transformation_ref", "definition_sha256", "derivative_claim"},
        "Transformation",
    )
    if (
        type(transformation["transformation_ref"]) is not str
        or _TRANSFORMATION.fullmatch(transformation["transformation_ref"]) is None
    ):
        raise _error("Transformation reference is invalid")
    _digest(transformation["definition_sha256"])
    if type(transformation["derivative_claim"]) is not str or transformation[
        "derivative_claim"
    ] not in {"derived_candidate", "redacted_candidate"}:
        raise _error("Only unverified derivative candidate claims are supported")
    return value


def _prefixes(evidence: bytes) -> dict[str, Any]:
    prefix = evidence[:MAXIMUM_PREFIX_BYTES]
    complete = sorted(name for name, marker in PREFIX_FEATURES.items() if prefix.startswith(marker))
    truncated = sorted(
        name
        for name, marker in PREFIX_FEATURES.items()
        if len(prefix) < len(marker) and marker.startswith(prefix)
    )
    status = (
        "ambiguous_prefix_observation"
        if len(complete) > 1 or complete and truncated
        else "known_prefix_observation"
        if complete
        else "truncated_prefix_observation"
        if truncated
        else "unknown_prefix_observation"
    )
    return {
        "status": status,
        "complete_prefix_refs": complete,
        "truncated_prefix_refs": truncated,
        "inspected_size_bytes": len(prefix),
        "type_verdict": "not_determined",
        "malware_safety_verdict": "not_assessed",
    }


def _address(body: dict[str, Any]) -> dict[str, Any]:
    domain, prefix = (
        (PREFIX_OBSERVATION_DOMAIN, "EPO")
        if body["kind"] == "passive_prefix_observation"
        else (DERIVATIVE_PROVENANCE_DOMAIN, "EDP")
    )
    digest = (
        "sha256:"
        + hashlib.sha256(_canonical({"domain": domain, "report": body}).encode("ascii")).hexdigest()
    )
    return {**body, "report_id": prefix + "-" + digest[7:39].upper(), "report_sha256": digest}


def _validated(raw: Any) -> dict[str, Any]:
    value = json.loads(_canonical(raw))
    _fields(
        value,
        {
            "schema_version",
            "kind",
            "report_id",
            "report_sha256",
            "environment_class",
            "source",
            "observation",
            "provenance",
            "transformation_status",
            "redaction_status",
            "effects",
            *_BOUNDARY,
        },
        "Content report",
    )
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise _error("Content report schema requires native version 1")
    _environment(value["environment_class"])
    _validate_source(value["source"])
    if (
        any(value[name] != expected for name, expected in _BOUNDARY.items())
        or value["effects"] != dict(EFFECTS)
        or value["transformation_status"] != "not_executed_or_verified"
        or value["redaction_status"] != "not_performed_or_verified"
    ):
        raise _error("Content report exceeds its non-authority boundary")
    if value["kind"] == "passive_prefix_observation":
        if value["provenance"] is not None:
            raise _error("Prefix observation cannot claim derivative provenance")
        observation = value["observation"]
        _fields(
            observation,
            {
                "status",
                "complete_prefix_refs",
                "truncated_prefix_refs",
                "inspected_size_bytes",
                "type_verdict",
                "malware_safety_verdict",
            },
            "Prefix observation",
        )
        complete, truncated = (
            observation["complete_prefix_refs"],
            observation["truncated_prefix_refs"],
        )
        for refs in (complete, truncated):
            if (
                type(refs) is not list
                or any(type(ref) is not str or ref not in PREFIX_FEATURES for ref in refs)
                or refs != sorted(set(refs))
            ):
                raise _error("Prefix references must be known, unique and ordered")
        size = observation["inspected_size_bytes"]
        expected_status = (
            "ambiguous_prefix_observation"
            if len(complete) > 1 or complete and truncated
            else "known_prefix_observation"
            if complete
            else "truncated_prefix_observation"
            if truncated
            else "unknown_prefix_observation"
        )
        if (
            type(size) is not int
            or size != min(value["source"]["evidence"]["evidence_size_bytes"], MAXIMUM_PREFIX_BYTES)
            or set(complete) & set(truncated)
            or any(len(PREFIX_FEATURES[ref]) > size for ref in complete)
            or any(len(PREFIX_FEATURES[ref]) <= size for ref in truncated)
            or observation["status"] != expected_status
            or observation["type_verdict"] != "not_determined"
            or observation["malware_safety_verdict"] != "not_assessed"
        ):
            raise _error("Prefix observation is inconsistent or claims a verdict")
        footprints = [PREFIX_FEATURES[ref] for ref in complete] + [
            PREFIX_FEATURES[ref][:size] for ref in truncated
        ]
        if any(
            not (left.startswith(right) or right.startswith(left))
            for left in footprints
            for right in footprints
        ):
            raise _error("Named prefix features cannot describe the same leading bytes")
    elif value["kind"] == "supplied_derivative_provenance":
        if value["observation"] is not None:
            raise _error("Derivative provenance cannot claim a prefix observation")
        _provenance(value["provenance"], value["source"])
    else:
        raise _error("Content report kind is unsupported")
    body = {key: item for key, item in value.items() if key not in {"report_id", "report_sha256"}}
    if _canonical(value) != _canonical(_address(body)):
        raise _error("Content report identity does not reproduce")
    return value


@dataclass(frozen=True, slots=True)
class ProviderEvidenceContentSafetyReport:
    """Unsigned detached reference metadata; construction authenticates nothing."""

    report_id: str
    report_sha256: str
    document_json: str

    def __post_init__(self) -> None:
        identifier, digest, document = _wrapper_metadata(
            self, ProviderEvidenceContentSafetyReport, "report_id", "report_sha256"
        )
        value = _validated(_document(document))
        if (
            identifier != value["report_id"]
            or digest != value["report_sha256"]
            or document != _canonical(value)
        ):
            raise _error("Content report wrapper does not reproduce")

    @classmethod
    def from_dict(cls, raw: Any) -> ProviderEvidenceContentSafetyReport:
        value = _validated(raw)
        return cls(value["report_id"], value["report_sha256"], _canonical(value))

    @classmethod
    def from_json(cls, document: str) -> ProviderEvidenceContentSafetyReport:
        return cls.from_dict(_document(document))

    def to_dict(self) -> dict[str, Any]:
        identifier, digest, document = _wrapper_metadata(
            self, ProviderEvidenceContentSafetyReport, "report_id", "report_sha256"
        )
        value = _validated(_document(document))
        if (
            identifier != value["report_id"]
            or digest != value["report_sha256"]
            or document != _canonical(value)
        ):
            raise _error("Content report wrapper does not reproduce")
        return value


def _report(
    kind: str, source: dict[str, Any], *, observation: Any = None, provenance: Any = None
) -> ProviderEvidenceContentSafetyReport:
    return ProviderEvidenceContentSafetyReport.from_dict(
        _address(
            {
                "schema_version": SCHEMA_VERSION,
                "kind": kind,
                "environment_class": ENVIRONMENT_CLASS,
                "source": source,
                "observation": observation,
                "provenance": provenance,
                "transformation_status": "not_executed_or_verified",
                "redaction_status": "not_performed_or_verified",
                "effects": dict(EFFECTS),
                **_BOUNDARY,
            }
        )
    )


def observe_provider_evidence_content_prefix(
    request: ProviderEvidenceRepositoryIngestRequest,
    lifecycle_policy: ProviderEvidenceLifecyclePolicy,
    evidence: bytes,
    *,
    environment_class: str,
) -> ProviderEvidenceContentSafetyReport:
    """Observe fixed prefix equality, never MIME, format validity or safety."""
    _environment(environment_class)
    evidence = _bytes(evidence)
    source = _sources(request, lifecycle_policy, evidence)
    return _report("passive_prefix_observation", source, observation=_prefixes(evidence))


def verify_provider_evidence_derivative_provenance(
    request: ProviderEvidenceRepositoryIngestRequest,
    lifecycle_policy: ProviderEvidenceLifecyclePolicy,
    source_evidence: bytes,
    derivative_evidence: bytes,
    *,
    provenance: dict[str, Any],
    environment_class: str,
) -> ProviderEvidenceContentSafetyReport:
    """Bind supplied derivative bytes and declared provenance; run no transform."""
    _environment(environment_class)
    source_evidence, derivative_evidence = _bytes(source_evidence), _bytes(derivative_evidence)
    declaration = json.loads(_canonical(provenance))
    source = _sources(request, lifecycle_policy, source_evidence)
    declaration = _provenance(declaration, source)
    if declaration["derivative"] != {
        "content_address": "sha256:" + hashlib.sha256(derivative_evidence).hexdigest(),
        "evidence_size_bytes": len(derivative_evidence),
    }:
        raise _error("Supplied derivative digest or size does not match")
    return _report("supplied_derivative_provenance", source, provenance=declaration)


def _replay(
    document: Any, expected: ProviderEvidenceContentSafetyReport
) -> ProviderEvidenceContentSafetyReport:
    if type(document) is ProviderEvidenceContentSafetyReport:
        raw = document.to_dict()
    elif type(document) is dict:
        raw = document
    else:
        raise _error("Content replay requires a native document or exact report")
    parsed = ProviderEvidenceContentSafetyReport.from_dict(raw)
    if parsed.document_json != expected.document_json:
        raise _error("Content report does not replay its supplied bytes and sources")
    return parsed


def verify_provider_evidence_content_observation_document(
    document: Any,
    *,
    request: ProviderEvidenceRepositoryIngestRequest,
    lifecycle_policy: ProviderEvidenceLifecyclePolicy,
    evidence: bytes,
    environment_class: str,
) -> ProviderEvidenceContentSafetyReport:
    """Replay unsigned prefix metadata against the explicit original inputs."""
    # Reject costly or nonnative metadata before any source hash reconstruction.
    raw = document.to_dict() if type(document) is ProviderEvidenceContentSafetyReport else document
    _validated(raw)
    return _replay(
        raw,
        observe_provider_evidence_content_prefix(
            request, lifecycle_policy, evidence, environment_class=environment_class
        ),
    )


def verify_provider_evidence_derivative_provenance_document(
    document: Any,
    *,
    request: ProviderEvidenceRepositoryIngestRequest,
    lifecycle_policy: ProviderEvidenceLifecyclePolicy,
    source_evidence: bytes,
    derivative_evidence: bytes,
    provenance: dict[str, Any],
    environment_class: str,
) -> ProviderEvidenceContentSafetyReport:
    """Replay supplied-byte provenance, not transformation or redaction success."""
    raw = document.to_dict() if type(document) is ProviderEvidenceContentSafetyReport else document
    _validated(raw)
    return _replay(
        raw,
        verify_provider_evidence_derivative_provenance(
            request,
            lifecycle_policy,
            source_evidence,
            derivative_evidence,
            provenance=provenance,
            environment_class=environment_class,
        ),
    )


__all__ = [
    "ENVIRONMENT_CLASS",
    "MAXIMUM_DOCUMENT_BYTES",
    "MAXIMUM_PREFIX_BYTES",
    "PREFIX_FEATURES",
    "ProviderEvidenceContentSafetyError",
    "ProviderEvidenceContentSafetyReport",
    "observe_provider_evidence_content_prefix",
    "verify_provider_evidence_content_observation_document",
    "verify_provider_evidence_derivative_provenance",
    "verify_provider_evidence_derivative_provenance_document",
]
