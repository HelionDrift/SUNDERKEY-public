"""Bounded reference-only samples of the D013 core-ingest protocol."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from .collaboration_executor_provider_evidence import MAXIMUM_EVIDENCE_BYTES
from .errors import SunderkeyError
from .provider_evidence_custody_decision import ProviderEvidenceCustodyDecisionRecord
from .provider_evidence_repository import (
    ProviderEvidenceRepositoryAdapter,
    ProviderEvidenceRepositoryIngestReceipt,
    ProviderEvidenceRepositoryIngestRequest,
    validate_provider_evidence_repository_ingest_bytes,
    validate_provider_evidence_repository_ingest_receipt,
)

ENVIRONMENT_CLASS = "reference_simulation_nonqualifying"
MAXIMUM_CASES = 12
MAXIMUM_CALLS = 16
MAXIMUM_DOCUMENT_BYTES = 64 * 1024
REPORT_DOMAIN = "sunderkey.provider-evidence-repository-conformance.v1"
CASE_BEHAVIORS = MappingProxyType(
    {
        "accepted_ingest": "accepted_reference_receipt",
        "identical_replay": "identical_reference_replay",
        "pre_invocation_rejection": "rejected_before_invocation",
        "malformed_result_rejection": "invalid_result_rejected",
        "late_mutation_rejection": "late_input_mutation_rejected",
        "failed_acknowledgement": "failed_provider_report",
        "rejected_acknowledgement": "rejected_provider_report",
        "lost_acknowledgement": "ambiguous_no_acknowledgement",
    }
)
_OBSERVATIONS = frozenset(CASE_BEHAVIORS.values()) | {
    "unexpected_valid_input",
    "unexpected_receipt_outcome",
    "replay_binding_mismatch",
}
_CONTROLS = (
    "conditional_create",
    "immutable_version",
    "envelope_encryption",
    "quarantine",
    "retention_policy",
    "residency_policy",
)
_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_CASE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class ProviderEvidenceRepositoryConformanceError(SunderkeyError):
    """Invalid reference fixtures or conformance report material."""


def _error(label: str) -> ProviderEvidenceRepositoryConformanceError:
    return ProviderEvidenceRepositoryConformanceError(label)


def _bounded_json(value: Any) -> str:
    # Charge the full serialized tree, including repeated shared subtrees, before
    # serialization. Only native JSON primitives are permitted in this leaf.
    remaining = MAXIMUM_DOCUMENT_BYTES
    nodes = 0

    def charge(amount: int) -> None:
        nonlocal remaining
        remaining -= amount
        if remaining < 0:
            raise _error("Conformance document exceeds its byte bound")

    def text_size(item: str) -> None:
        if len(item) > 8192:
            raise _error("Conformance string exceeds its bound")
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
        if depth > 16 or nodes > 4096:
            raise _error("Conformance document exceeds its structural bound")
        kind = type(item)
        if kind is dict:
            charge(2 + max(0, len(item) - 1) + len(item))
            for key, child in item.items():
                if type(key) is not str:
                    raise _error("Conformance object keys must be native strings")
                text_size(key)
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
                raise _error("Conformance integer exceeds its bound")
            charge(len(str(item)))
        elif item is None:
            charge(4)
        else:
            raise _error("Conformance material requires native JSON primitives")

    visit(value, 0)
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _load(document: Any) -> dict[str, Any]:
    if type(document) is not str or len(document) > MAXIMUM_DOCUMENT_BYTES:
        raise _error("Conformance source document must be a bounded native string")
    try:
        if len(document.encode("utf-8")) > MAXIMUM_DOCUMENT_BYTES:
            raise _error("Conformance source document exceeds its byte bound")

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in items:
                if key in result:
                    raise _error("Conformance source contains duplicate keys")
                result[key] = item
            return result

        def integer(text: str) -> int:
            if len(text) > 20:
                raise _error("Conformance integer exceeds its bound")
            return int(text)

        def unsupported(_: str) -> Any:
            raise _error("Conformance source does not support floating-point values")

        value = json.loads(
            document,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
        if type(value) is not dict:
            raise _error("Conformance source must be an object")
        _bounded_json(value)
        return value
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise _error("Conformance source is not bounded strict JSON") from exc


def _fields(value: Any, fields: set[str], label: str) -> None:
    if type(value) is not dict or set(value) != fields:
        raise _error(f"{label} fields are invalid")


def _digest(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise _error("Conformance digest must be native canonical SHA-256")
    return value


def _hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_bounded_json(value).encode("ascii")).hexdigest()


def _timestamp(value: Any) -> datetime:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise _error("Conformance timestamps require native canonical UTC strings")
    try:
        return datetime.fromisoformat(value[:-1]).replace(tzinfo=UTC)
    except ValueError as exc:
        raise _error("Conformance timestamp is invalid") from exc


def _capture(value: Any, family: type, id_field: str, hash_field: str) -> dict[str, Any]:
    if type(value) is not family:
        raise _error("Conformance source requires the exact existing wrapper family")
    identifier = getattr(value, id_field)
    digest = getattr(value, hash_field)
    if type(identifier) is not str:
        raise _error("Conformance wrapper identity must be a native string")
    _digest(digest)
    document = _load(value.document_json)
    return {
        "identifier": identifier,
        "digest": digest,
        "document_json": value.document_json,
        "document": document,
    }


def _rebuild(value: Any, family: type, id_field: str, hash_field: str) -> Any:
    source = _capture(value, family, id_field, hash_field)
    document = source["document"]
    if type(document.get("schema_version")) is not int:
        raise _error("Conformance source schema must be a native integer")
    if family is ProviderEvidenceCustodyDecisionRecord:
        alignment = document.get("recommendation_alignment")
        if type(alignment) is not dict or any(
            type(alignment.get(key)) is not int
            for key in ("selected_option_count", "selected_recommended_option_count")
        ):
            raise _error("Conformance decision counts must be native integers")
    elif family is ProviderEvidenceRepositoryIngestRequest:
        verification = document.get("evidence_verification")
        if type(verification) is not dict or any(
            type(verification.get(key)) is not int
            for key in ("schema_version", "evidence_size_bytes")
        ):
            raise _error("Conformance verification fields must be native integers")
    else:
        binding = document.get("ingest_request")
        if type(binding) is not dict or type(binding.get("evidence_size_bytes")) is not int:
            raise _error("Conformance receipt size must be a native integer")
    try:
        rebuilt = family.from_dict(document)
    except (SunderkeyError, TypeError, ValueError, AttributeError) as exc:
        raise _error("Conformance source does not reproduce its existing contract") from exc
    if (
        source["identifier"] != getattr(rebuilt, id_field)
        or source["digest"] != getattr(rebuilt, hash_field)
        or source["document_json"] != rebuilt.document_json
    ):
        raise _error("Conformance wrapper metadata or canonical document is inconsistent")
    return rebuilt


@dataclass(frozen=True)
class ProviderEvidenceRepositoryConformanceCase:
    """One explicitly supplied inert adapter scenario, not a provider backend."""

    case_id: str
    expected_behavior: str
    adapter: ProviderEvidenceRepositoryAdapter
    request: ProviderEvidenceRepositoryIngestRequest
    evidence: bytes
    attempted_at: str


def _prepare(
    request: ProviderEvidenceRepositoryIngestRequest,
    evidence: bytes,
    attempted_at: str,
    decision: ProviderEvidenceCustodyDecisionRecord,
) -> ProviderEvidenceRepositoryIngestRequest:
    parsed = _rebuild(
        request, ProviderEvidenceRepositoryIngestRequest, "request_id", "request_sha256"
    )
    document = parsed.to_dict()
    if document["custody_decision"] != {
        "record_id": decision.record_id,
        "record_sha256": decision.record_sha256,
    }:
        raise _error("Conformance request does not bind the supplied D013 decision")
    for timestamp in (
        document["requested_at"],
        document["expires_at"],
        document["evidence_verification"]["verified_at"],
    ):
        _timestamp(timestamp)
    at = _timestamp(attempted_at)
    if not _timestamp(document["requested_at"]) <= at < _timestamp(document["expires_at"]):
        raise _error("Conformance invocation is outside the request time window")
    try:
        validate_provider_evidence_repository_ingest_bytes(parsed, evidence)
    except (SunderkeyError, TypeError, ValueError) as exc:
        raise _error("Conformance evidence does not match request size and SHA-256") from exc
    return parsed


def _source_binding(source: dict[str, Any], prefix: str) -> dict[str, str]:
    return {
        f"{prefix}_id": source["identifier"],
        f"{prefix}_sha256": source["digest"],
        "document_sha256": _hash(source["document"]),
    }


def _unchanged(value: Any, source: dict[str, Any], family: type, prefix: str) -> bool:
    try:
        return _capture(value, family, f"{prefix}_id", f"{prefix}_sha256") == source
    except (SunderkeyError, TypeError, ValueError, AttributeError):
        return False


def _receipt(
    request: ProviderEvidenceRepositoryIngestRequest, value: Any, attempted_at: str
) -> dict[str, Any]:
    parsed = _rebuild(
        value, ProviderEvidenceRepositoryIngestReceipt, "receipt_id", "receipt_sha256"
    )
    try:
        parsed = validate_provider_evidence_repository_ingest_receipt(request, parsed)
    except (SunderkeyError, TypeError, ValueError) as exc:
        raise _error("Conformance receipt does not bind the exact request") from exc
    document = parsed.to_dict()
    if not (
        _timestamp(attempted_at)
        <= _timestamp(document["responded_at"])
        < _timestamp(request.to_dict()["expires_at"])
    ):
        raise _error("Conformance receipt is outside the sampled request time window")
    return document


def _outcome(document: dict[str, Any]) -> str:
    return {
        "accepted": "accepted_reference_receipt",
        "already_exists_same_digest": "unexpected_receipt_outcome",
        "failed": "failed_provider_report",
        "rejected": "rejected_provider_report",
    }[document["outcome"]]


def run_provider_evidence_repository_conformance(
    *,
    environment_class: str,
    decision: ProviderEvidenceCustodyDecisionRecord,
    cases: tuple[ProviderEvidenceRepositoryConformanceCase, ...],
    maximum_calls: int,
) -> ProviderEvidenceRepositoryConformanceReport:
    """Sample only explicit inert adapters, with no retries or default backend."""

    if type(environment_class) is not str or environment_class != ENVIRONMENT_CLASS:
        raise _error("Conformance requires the reference-simulation-only environment")
    if type(maximum_calls) is not int or not 0 <= maximum_calls <= MAXIMUM_CALLS:
        raise _error("Conformance maximum_calls must be a native bounded integer")
    if type(cases) is not tuple or not 1 <= len(cases) <= MAXIMUM_CASES:
        raise _error("Conformance requires a bounded tuple of explicit cases")
    parsed_decision = _rebuild(
        decision, ProviderEvidenceCustodyDecisionRecord, "record_id", "record_sha256"
    )
    if (
        parsed_decision.to_dict()["recommendation_alignment"]["all_recommended_options_selected"]
        is not True
    ):
        raise _error("Conformance requires the approved recommended D013 contract bundle")
    decision_source = _capture(
        decision, ProviderEvidenceCustodyDecisionRecord, "record_id", "record_sha256"
    )
    prepared: list[tuple[Any, ...]] = []
    identifiers: set[str] = set()
    potential_calls = 0
    # Preflight every scenario before the first adapter invocation. A negative
    # input scenario must be explicitly declared as pre_invocation_rejection.
    for case in cases:
        if type(case) is not ProviderEvidenceRepositoryConformanceCase:
            raise _error("Conformance cases require the exact fixture family")
        if type(case.case_id) is not str or _CASE_ID.fullmatch(case.case_id) is None:
            raise _error("Conformance case identity is invalid")
        if case.case_id in identifiers:
            raise _error("Conformance case identities must be unique")
        identifiers.add(case.case_id)
        if type(case.expected_behavior) is not str or case.expected_behavior not in CASE_BEHAVIORS:
            raise _error("Conformance expected behavior is unsupported")
        if (
            type(case.evidence) is not bytes
            or not 1 <= len(case.evidence) <= MAXIMUM_EVIDENCE_BYTES
        ):
            raise _error("Conformance evidence requires bounded native opaque bytes")
        _timestamp(case.attempted_at)
        source = _capture(
            case.request, ProviderEvidenceRepositoryIngestRequest, "request_id", "request_sha256"
        )
        if re.fullmatch(r"EIR-[0-9A-F]{32}", source["identifier"]) is None:
            raise _error("Conformance supplied request identity is invalid")
        try:
            request = _prepare(case.request, case.evidence, case.attempted_at, parsed_decision)
        except ProviderEvidenceRepositoryConformanceError:
            if case.expected_behavior != "pre_invocation_rejection":
                raise
            request = None
        if case.expected_behavior != "pre_invocation_rejection":
            potential_calls += 2 if case.expected_behavior == "identical_replay" else 1
        prepared.append(
            (
                case,
                source,
                request,
                case.case_id,
                case.expected_behavior,
                case.attempted_at,
                case.adapter,
                case.evidence,
                case.request,
            )
        )
    if potential_calls > maximum_calls:
        raise _error("Conformance case plan exceeds the explicit maximum-call ceiling")
    for _, _, _, _, _, _, adapter, _, _ in prepared:
        if not callable(getattr(adapter, "put_quarantined", None)):
            raise _error("Conformance requires an explicit caller-supplied inert adapter")

    results: list[dict[str, Any]] = []
    total_calls = 0
    for (
        case,
        source,
        request,
        case_id,
        behavior,
        at,
        adapter,
        evidence,
        original_request,
    ) in prepared:
        # These native values are captured before adapter code can alter a frozen
        # wrapper with object.__setattr__. This is not a concurrency sandbox.
        def unchanged_inputs() -> bool:
            return (
                type(case) is ProviderEvidenceRepositoryConformanceCase
                and _unchanged(
                    original_request, source, ProviderEvidenceRepositoryIngestRequest, "request"
                )
                and _unchanged(
                    decision, decision_source, ProviderEvidenceCustodyDecisionRecord, "record"
                )
                and type(case.case_id) is str
                and case.case_id == case_id
                and type(case.expected_behavior) is str
                and case.expected_behavior == behavior
                and type(case.attempted_at) is str
                and case.attempted_at == at
                and case.adapter is adapter
                and case.evidence is evidence
                and case.request is original_request
            )

        receipts: list[dict[str, Any]] = []
        calls = 0
        observation = "rejected_before_invocation" if request is None else "unexpected_valid_input"
        if request is not None and behavior != "pre_invocation_rejection":
            request_source = _capture(
                request, ProviderEvidenceRepositoryIngestRequest, "request_id", "request_sha256"
            )
            for _ in range(2 if behavior == "identical_replay" else 1):
                if not unchanged_inputs():
                    observation = "late_input_mutation_rejected"
                    break
                try:
                    _prepare(request, evidence, at, parsed_decision)
                except ProviderEvidenceRepositoryConformanceError:
                    observation = "late_input_mutation_rejected"
                    break
                if total_calls >= maximum_calls:
                    raise _error("Conformance maximum-call ceiling exhausted")
                calls += 1
                total_calls += 1
                returned = None
                acknowledged = False
                try:
                    returned = adapter.put_quarantined(request, evidence)
                    acknowledged = True
                except Exception:
                    # A failure or lost acknowledgement does not prove that an
                    # object was not written. No retry or fallback follows.
                    observation = "ambiguous_no_acknowledgement"
                if not (
                    _unchanged(
                        request, request_source, ProviderEvidenceRepositoryIngestRequest, "request"
                    )
                    and unchanged_inputs()
                ):
                    observation = "late_input_mutation_rejected"
                    break
                if not acknowledged:
                    break
                try:
                    receipt = _receipt(request, returned, at)
                except (SunderkeyError, TypeError, ValueError, AttributeError):
                    observation = "invalid_result_rejected"
                    break
                receipts.append(receipt)
                observation = _outcome(receipt)
                if (
                    behavior != "identical_replay"
                    or len(receipts) == 1
                    and receipt["outcome"] != "accepted"
                ):
                    break
                if len(receipts) == 2:
                    if receipt["outcome"] != "already_exists_same_digest":
                        observation = "unexpected_receipt_outcome"
                    elif any(
                        receipt[field] != receipts[0][field]
                        for field in ("provider", "repository_object", "ingest_request")
                    ):
                        observation = "replay_binding_mismatch"
                    else:
                        observation = "identical_reference_replay"
        results.append(
            {
                "case_id": case_id,
                "expected_behavior": behavior,
                "supplied_request": _source_binding(source, "request"),
                "supplied_evidence": {
                    "sha256": "sha256:" + hashlib.sha256(evidence).hexdigest(),
                    "size_bytes": len(evidence),
                },
                "attempted_at": at,
                "request_validation": "rejected_before_invocation"
                if request is None
                else "validated",
                "adapter_call_count": calls,
                "observation": observation,
                "case_status": "passed" if observation == CASE_BEHAVIORS[behavior] else "failed",
                "receipts": receipts,
            }
        )
    return _report(_source_binding(decision_source, "record"), results, maximum_calls)


def _report(
    decision: dict[str, str], results: list[dict[str, Any]], maximum_calls: int
) -> ProviderEvidenceRepositoryConformanceReport:
    body = _report_body(decision, results, maximum_calls)
    digest = _hash({"domain": REPORT_DOMAIN, "report": body})
    document = {**body, "report_id": "EIC-" + digest[7:39].upper(), "report_sha256": digest}
    return ProviderEvidenceRepositoryConformanceReport.from_dict(document)


def _validate_report(raw: Any) -> dict[str, Any]:
    # Canonicalize only after an aggregate byte/shape bound and native-type check.
    value = _load(_bounded_json(raw))
    fields = {
        "schema_version",
        "report_id",
        "report_sha256",
        "environment_class",
        "custody_decision",
        "case_results",
        "maximum_calls",
        "adapter_call_count",
        "summary",
        "conformance_status",
        "provider_controls",
        "same_object_conflict_status",
        "authentication_status",
        "custody_effect",
        "authority_effect",
        "runtime_effect",
        "qualification_effect",
        "raw_evidence_in_report",
        "observed_live_acceptance",
    }
    _fields(value, fields, "Conformance report")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise _error("Conformance report schema is invalid")
    cases = value["case_results"]
    if type(cases) is not list or not 1 <= len(cases) <= MAXIMUM_CASES:
        raise _error("Conformance report cases are invalid")
    maximum_calls = value["maximum_calls"]
    if type(maximum_calls) is not int or not 0 <= maximum_calls <= MAXIMUM_CALLS:
        raise _error("Conformance report maximum-call ceiling is invalid")
    _fields(
        value["custody_decision"],
        {"record_id", "record_sha256", "document_sha256"},
        "Decision binding",
    )
    decision = value["custody_decision"]
    if (
        type(decision["record_id"]) is not str
        or re.fullmatch(r"ECR-[0-9A-F]{32}", decision["record_id"]) is None
    ):
        raise _error("Conformance report decision identity is invalid")
    _digest(decision["record_sha256"])
    _digest(decision["document_sha256"])
    identifiers: set[str] = set()
    planned_calls = 0
    observed_calls = 0
    for case in cases:
        _fields(
            case,
            {
                "case_id",
                "expected_behavior",
                "supplied_request",
                "supplied_evidence",
                "attempted_at",
                "request_validation",
                "adapter_call_count",
                "observation",
                "case_status",
                "receipts",
            },
            "Conformance case result",
        )
        if (
            type(case["case_id"]) is not str
            or _CASE_ID.fullmatch(case["case_id"]) is None
            or case["case_id"] in identifiers
        ):
            raise _error("Conformance report case identity is invalid")
        identifiers.add(case["case_id"])
        behavior = case["expected_behavior"]
        if (
            type(behavior) is not str
            or behavior not in CASE_BEHAVIORS
            or type(case["observation"]) is not str
            or case["observation"] not in _OBSERVATIONS
        ):
            raise _error("Conformance report behavior is invalid")
        calls = case["adapter_call_count"]
        planned = (
            0
            if behavior == "pre_invocation_rejection"
            else 2
            if behavior == "identical_replay"
            else 1
        )
        if type(calls) is not int or not 0 <= calls <= planned:
            raise _error("Conformance report case call count is invalid")
        planned_calls += planned
        observed_calls += calls
        _fields(
            case["supplied_request"],
            {"request_id", "request_sha256", "document_sha256"},
            "Request binding",
        )
        request = case["supplied_request"]
        if (
            type(request["request_id"]) is not str
            or re.fullmatch(r"EIR-[0-9A-F]{32}", request["request_id"]) is None
        ):
            raise _error("Conformance report request identity is invalid")
        _digest(request["request_sha256"])
        _digest(request["document_sha256"])
        _fields(case["supplied_evidence"], {"sha256", "size_bytes"}, "Evidence binding")
        evidence = case["supplied_evidence"]
        _digest(evidence["sha256"])
        if (
            type(evidence["size_bytes"]) is not int
            or not 1 <= evidence["size_bytes"] <= MAXIMUM_EVIDENCE_BYTES
        ):
            raise _error("Conformance report evidence size is invalid")
        _timestamp(case["attempted_at"])
        if type(case["request_validation"]) is not str or case["request_validation"] not in {
            "validated",
            "rejected_before_invocation",
        }:
            raise _error("Conformance report request validation is invalid")
        if case["request_validation"] == "rejected_before_invocation" and (
            calls != 0 or case["observation"] != "rejected_before_invocation"
        ):
            raise _error("Conformance report rejected input has inconsistent observations")
        receipts = case["receipts"]
        if type(receipts) is not list or len(receipts) > calls:
            raise _error("Conformance report receipt count is invalid")
        for receipt in receipts:
            try:
                parsed_receipt = ProviderEvidenceRepositoryIngestReceipt.from_dict(receipt)
            except (SunderkeyError, TypeError, ValueError, AttributeError) as exc:
                raise _error("Conformance report receipt is invalid") from exc
            parsed = _rebuild(
                parsed_receipt,
                ProviderEvidenceRepositoryIngestReceipt,
                "receipt_id",
                "receipt_sha256",
            )
            if _bounded_json(parsed.to_dict()) != _bounded_json(receipt) or receipt[
                "ingest_request"
            ] != {
                "request_id": request["request_id"],
                "request_sha256": request["request_sha256"],
                "content_address": evidence["sha256"],
                "evidence_size_bytes": evidence["size_bytes"],
            }:
                raise _error("Conformance report receipt correlation is invalid")
            if _timestamp(receipt["responded_at"]) < _timestamp(case["attempted_at"]):
                raise _error("Conformance report receipt precedes its sampled invocation")
        if case["case_status"] != (
            "passed" if case["observation"] == CASE_BEHAVIORS[behavior] else "failed"
        ):
            raise _error("Conformance report case status is invalid")
        _validate_observation(case)
    if planned_calls > maximum_calls or observed_calls > maximum_calls:
        raise _error("Conformance report exceeds its explicit maximum-call ceiling")
    expected = _report_body(decision, cases, maximum_calls)
    if _bounded_json(
        {key: item for key, item in value.items() if key not in {"report_id", "report_sha256"}}
    ) != _bounded_json(expected):
        raise _error("Conformance report summary or non-authority boundary is invalid")
    digest = _hash({"domain": REPORT_DOMAIN, "report": expected})
    if value["report_sha256"] != digest or value["report_id"] != "EIC-" + digest[7:39].upper():
        raise _error("Conformance report content address is invalid")
    return value


def _validate_observation(case: dict[str, Any]) -> None:
    calls, receipts, observation = case["adapter_call_count"], case["receipts"], case["observation"]
    valid = False
    if observation == "rejected_before_invocation":
        valid = calls == 0 and not receipts and case["request_validation"] == observation
    elif observation == "unexpected_valid_input":
        valid = (
            calls == 0 and not receipts and case["expected_behavior"] == "pre_invocation_rejection"
        )
    elif observation in {"invalid_result_rejected", "ambiguous_no_acknowledgement"}:
        valid = calls > 0 and len(receipts) == calls - 1
    elif observation == "late_input_mutation_rejected":
        valid = len(receipts) == max(0, calls - 1) or (
            case["expected_behavior"] == "identical_replay"
            and calls == 1
            and len(receipts) == 1
            and receipts[0]["outcome"] == "accepted"
        )
    elif observation in {
        "accepted_reference_receipt",
        "failed_provider_report",
        "rejected_provider_report",
    }:
        expected = {
            "accepted_reference_receipt": "accepted",
            "failed_provider_report": "failed",
            "rejected_provider_report": "rejected",
        }[observation]
        valid = calls > 0 and len(receipts) == calls and receipts[-1]["outcome"] == expected
    elif observation == "unexpected_receipt_outcome":
        valid = (
            calls > 0
            and len(receipts) == calls
            and (
                receipts[-1]["outcome"] == "already_exists_same_digest"
                or calls == 2
                and receipts[-1]["outcome"] == "accepted"
            )
        )
    elif observation in {"identical_reference_replay", "replay_binding_mismatch"}:
        if (
            calls == 2
            and len(receipts) == 2
            and receipts[0]["outcome"] == "accepted"
            and receipts[1]["outcome"] == "already_exists_same_digest"
        ):
            same = all(
                receipts[0][key] == receipts[1][key]
                for key in ("provider", "repository_object", "ingest_request")
            )
            valid = same if observation == "identical_reference_replay" else not same
    if not valid or calls and case["request_validation"] != "validated":
        raise _error("Conformance report observation does not reproduce its sampled shape")


def _report_body(
    decision: dict[str, str], results: list[dict[str, Any]], maximum_calls: int
) -> dict[str, Any]:
    passed = sum(item["case_status"] == "passed" for item in results)
    return {
        "schema_version": 1,
        "environment_class": ENVIRONMENT_CLASS,
        "custody_decision": decision,
        "case_results": results,
        "maximum_calls": maximum_calls,
        "adapter_call_count": sum(item["adapter_call_count"] for item in results),
        "summary": {
            "case_count": len(results),
            "passed_case_count": passed,
            "failed_case_count": len(results) - passed,
        },
        "conformance_status": "reference_simulation_cases_passed"
        if passed == len(results)
        else "reference_simulation_cases_failed",
        "provider_controls": dict.fromkeys(_CONTROLS, "unverified"),
        "same_object_conflict_status": "not_expressible_by_ingest_request",
        "authentication_status": "unsigned_reference_observations",
        "custody_effect": "none",
        "authority_effect": "none",
        "runtime_effect": "none",
        "qualification_effect": "none",
        "raw_evidence_in_report": False,
        "observed_live_acceptance": False,
    }


@dataclass(frozen=True)
class ProviderEvidenceRepositoryConformanceReport:
    """A detached unsigned content address, never accepted repository custody."""

    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ProviderEvidenceRepositoryConformanceReport:
        document = _validate_report(raw)
        return cls(document["report_id"], document["report_sha256"], _bounded_json(document))

    def to_dict(self) -> dict[str, Any]:
        if type(self.report_id) is not str or type(self.report_sha256) is not str:
            raise _error("Conformance report wrapper requires native metadata")
        document = _validate_report(_load(self.document_json))
        if (
            self.report_id != document["report_id"]
            or self.report_sha256 != document["report_sha256"]
            or self.document_json != _bounded_json(document)
        ):
            raise _error("Conformance report wrapper metadata is inconsistent")
        return document


__all__ = [
    "CASE_BEHAVIORS",
    "ENVIRONMENT_CLASS",
    "MAXIMUM_CALLS",
    "MAXIMUM_CASES",
    "ProviderEvidenceRepositoryConformanceCase",
    "ProviderEvidenceRepositoryConformanceError",
    "ProviderEvidenceRepositoryConformanceReport",
    "run_provider_evidence_repository_conformance",
]
