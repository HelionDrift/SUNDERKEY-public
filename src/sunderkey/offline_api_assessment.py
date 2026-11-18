"""Correlate one synthetic API adapter run with independent evidence validation.

This module does not acquire evidence, contact a target, publish a finding, or
grant execution or qualification authority. Its input is caller-supplied,
already captured synthetic evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .candidate_adapter_sdk import AdapterInvocation, AdapterManifest, AdapterResult
from .errors import QualificationError
from .finding_validators import (
    DEFAULT_REGISTRY,
    AuthorizationDifferentialValidator,
    EvidenceRecord,
    FindingValidationError,
    FindingValidationRequest,
    FindingValidationResult,
)
from .reference_adapters import OfflineReferenceAdapter, analyze_api_authorization

API_PROFILE_ID = "AOE-GB-D06-S09"
API_TECHNIQUE_ID = "AT3-GB-D06-S09-01"
RESULT_DOMAIN = "sunderkey.offline-api-assessment.v1"
RETEST_DOMAIN = "sunderkey.offline-api-retest.v1"
BATCH_DOMAIN = "sunderkey.offline-api-assessment-batch.v1"
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
SOURCE_SESSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{1,255}\Z")
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
EVIDENCE_ATTRIBUTES = frozenset({"principal_id", "object_id", "action", "expected_access"})
RECEIPT_EVIDENCE_ATTRIBUTES = EVIDENCE_ATTRIBUTES | frozenset(
    {
        "source_receipt_sha256",
        "source_session_id",
        "source_scope_id",
        "source_scope_sha256",
        "source_target_id",
        "source_target_sha256",
    }
)
NO_EFFECTS = {
    "authority": "none",
    "deployment": "none",
    "finding_publication": "none",
    "network": "none",
    "qualification": "none",
    "target_execution": "none",
}


class OfflineApiAssessmentError(ValueError):
    """Raised when a synthetic API assessment cannot be correlated safely."""


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise OfflineApiAssessmentError(f"{label} must be a bounded opaque identifier")
    return value


def _digest(value: Mapping[str, Any]) -> str:
    document = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(document.encode("ascii")).hexdigest()


def _same_json(value: Any, expected: Mapping[str, Any]) -> bool:
    if not isinstance(value, Mapping):
        return False
    try:
        return json.dumps(
            dict(value), ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
        ) == json.dumps(
            expected, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError):
        return False


@dataclass(frozen=True, slots=True)
class OfflineApiAssessmentResult:
    schema_version: int
    case_id: str
    mission_id: str
    target_id: str
    scope_id: str
    invocation_id: str
    manifest_sha256: str
    adapter_result_sha256: str
    validator_result_sha256: str
    evidence_sha256s: tuple[str, ...]
    adapter_disposition: str
    validator_state: str
    disposition: str
    result_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "mission_id": self.mission_id,
            "target_id": self.target_id,
            "scope_id": self.scope_id,
            "invocation_id": self.invocation_id,
            "manifest_sha256": self.manifest_sha256,
            "adapter_result_sha256": self.adapter_result_sha256,
            "validator_result_sha256": self.validator_result_sha256,
            "evidence_sha256s": list(self.evidence_sha256s),
            "adapter_disposition": self.adapter_disposition,
            "validator_state": self.validator_state,
            "disposition": self.disposition,
            "effects": dict(NO_EFFECTS),
            "result_sha256": self.result_sha256,
        }


@dataclass(frozen=True, slots=True)
class OfflineApiRetestResult:
    schema_version: int
    prior_result_sha256: str
    second_result_sha256: str
    binding_sha256: str
    observation_change: str
    result_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "prior_result_sha256": self.prior_result_sha256,
            "second_result_sha256": self.second_result_sha256,
            "binding_sha256": self.binding_sha256,
            "observation_change": self.observation_change,
            "effects": dict(NO_EFFECTS),
            "result_sha256": self.result_sha256,
        }


@dataclass(frozen=True, slots=True)
class OfflineApiCaseSource:
    case_id: str
    invocation: AdapterInvocation
    evidence: tuple[EvidenceRecord, ...]
    result: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class OfflineApiBatchCase:
    case_id: str
    target_id: str
    result_sha256: str
    disposition: str
    binding_sha256: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "target_id": self.target_id,
            "result_sha256": self.result_sha256,
            "disposition": self.disposition,
            "binding_sha256": self.binding_sha256,
        }


@dataclass(frozen=True, slots=True)
class OfflineApiAssessmentBatch:
    schema_version: int
    mission_id: str
    scope_id: str
    manifest_sha256: str
    cases: tuple[OfflineApiBatchCase, ...]
    disposition_counts: tuple[tuple[str, int], ...]
    review_candidate_case_ids: tuple[str, ...]
    mixed_observation_binding_sha256s: tuple[str, ...]
    batch_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mission_id": self.mission_id,
            "scope_id": self.scope_id,
            "manifest_sha256": self.manifest_sha256,
            "cases": [case.to_dict() for case in self.cases],
            "disposition_counts": dict(self.disposition_counts),
            "review_candidate_case_ids": list(self.review_candidate_case_ids),
            "mixed_observation_binding_sha256s": list(self.mixed_observation_binding_sha256s),
            "effects": dict(NO_EFFECTS),
            "batch_sha256": self.batch_sha256,
        }


def _validate_evidence(records: Sequence[EvidenceRecord]) -> tuple[EvidenceRecord, ...]:
    if not isinstance(records, (list, tuple)) or not 1 <= len(records) <= 64:
        raise OfflineApiAssessmentError("one to 64 response records are required")
    if any(not isinstance(record, EvidenceRecord) for record in records):
        raise OfflineApiAssessmentError("all records must be typed evidence")
    verified: list[EvidenceRecord] = []
    for record in records:
        try:
            verified.append(
                EvidenceRecord.from_dict(
                    {
                        "evidence_id": record.evidence_id,
                        "content": record.content,
                        "content_sha256": record.content_sha256,
                        "media_type": record.media_type,
                        "role": record.role,
                        "status_code": record.status_code,
                        "headers": record.headers,
                        "attributes": record.attributes,
                        "evidence_sha256": record.evidence_sha256,
                    }
                )
            )
        except FindingValidationError as exc:
            raise OfflineApiAssessmentError("evidence content address is invalid") from exc
    ordered = tuple(sorted(verified, key=lambda record: record.evidence_id))
    if len({record.evidence_id for record in ordered}) != len(ordered):
        raise OfflineApiAssessmentError("evidence IDs must be unique")
    if len({record.evidence_sha256 for record in ordered}) != len(ordered):
        raise OfflineApiAssessmentError("evidence records must be distinct")
    for record in ordered:
        if record.role not in {"response", "control"} or record.status_code is None:
            raise OfflineApiAssessmentError("typed HTTP response evidence is required")
        attributes = record.attributes
        if frozenset(attributes) not in {EVIDENCE_ATTRIBUTES, RECEIPT_EVIDENCE_ATTRIBUTES}:
            raise OfflineApiAssessmentError("API evidence attributes are invalid")
        for key in ("principal_id", "object_id", "action"):
            _identifier(attributes[key], key)
        if type(attributes["expected_access"]) is not bool:
            raise OfflineApiAssessmentError("expected_access must be boolean")
        if "source_receipt_sha256" in attributes and (
            not isinstance(attributes["source_receipt_sha256"], str)
            or SHA256_RE.fullmatch(attributes["source_receipt_sha256"]) is None
            or not isinstance(attributes["source_session_id"], str)
            or SOURCE_SESSION_RE.fullmatch(attributes["source_session_id"]) is None
            or not isinstance(attributes["source_scope_sha256"], str)
            or SHA256_RE.fullmatch(attributes["source_scope_sha256"]) is None
            or not isinstance(attributes["source_target_sha256"], str)
            or SHA256_RE.fullmatch(attributes["source_target_sha256"]) is None
        ):
            raise OfflineApiAssessmentError("receipt source attributes are invalid")
        if "source_receipt_sha256" in attributes:
            _identifier(attributes["source_scope_id"], "source scope ID")
            _identifier(attributes["source_target_id"], "source target ID")
    sourced = [record for record in ordered if "source_receipt_sha256" in record.attributes]
    if sourced:
        if len(sourced) != len(ordered):
            raise OfflineApiAssessmentError("receipt-sourced evidence cannot mix with unsourced")
        if len({record.attributes["source_receipt_sha256"] for record in sourced}) != len(sourced):
            raise OfflineApiAssessmentError("HTTP response receipt replay detected")
        if (
            len({record.attributes["source_scope_id"] for record in sourced}) != 1
            or len({record.attributes["source_scope_sha256"] for record in sourced}) != 1
            or len({record.attributes["source_target_id"] for record in sourced}) != 1
            or len({record.attributes["source_target_sha256"] for record in sourced}) != 1
        ):
            raise OfflineApiAssessmentError("receipt source context changed within case")
        principal_sessions: dict[str, str] = {}
        session_principals: dict[str, str] = {}
        for record in sourced:
            principal = record.attributes["principal_id"]
            session = record.attributes["source_session_id"]
            if principal in principal_sessions and principal_sessions[principal] != session:
                raise OfflineApiAssessmentError("principal changed receipt session")
            if session in session_principals and session_principals[session] != principal:
                raise OfflineApiAssessmentError("receipt session maps to multiple principals")
            principal_sessions[principal] = session
            session_principals[session] = principal
    return ordered


def _validate_cross_case_sources(
    case_records: Sequence[tuple[EvidenceRecord, ...]],
) -> None:
    sourced_modes: set[bool] = set()
    source_receipts: set[str] = set()
    source_scope_hashes: set[str] = set()
    source_target_hashes: dict[str, str] = {}
    source_session_principals: dict[str, str] = {}
    for records in case_records:
        sourced = "source_receipt_sha256" in records[0].attributes
        sourced_modes.add(sourced)
        if not sourced:
            continue
        for record in records:
            attributes = record.attributes
            receipt_digest = attributes["source_receipt_sha256"]
            if receipt_digest in source_receipts:
                raise OfflineApiAssessmentError("HTTP response receipt replay across cases")
            source_receipts.add(receipt_digest)
            source_scope_hashes.add(attributes["source_scope_sha256"])
            target_id = attributes["source_target_id"]
            target_hash = attributes["source_target_sha256"]
            if target_id in source_target_hashes and source_target_hashes[target_id] != target_hash:
                raise OfflineApiAssessmentError("cross-case source target digest changed")
            source_target_hashes[target_id] = target_hash
            session_id = attributes["source_session_id"]
            principal_id = attributes["principal_id"]
            if (
                session_id in source_session_principals
                and source_session_principals[session_id] != principal_id
            ):
                raise OfflineApiAssessmentError("cross-case receipt session changed principal")
            source_session_principals[session_id] = principal_id
    if len(sourced_modes) != 1:
        raise OfflineApiAssessmentError("receipt-sourced and unsourced cases cannot mix")
    if len(source_scope_hashes) > 1:
        raise OfflineApiAssessmentError("cross-case source scope digest changed")


def _expected_exchanges(records: tuple[EvidenceRecord, ...]) -> list[dict[str, Any]]:
    return [
        {
            "evidence_id": record.evidence_id,
            "subject_id": record.attributes["principal_id"],
            "object_id": record.attributes["object_id"],
            "expected_permitted": record.attributes["expected_access"],
            "status_code": record.status_code,
        }
        for record in records
    ]


def _disposition(adapter: AdapterResult, validator: FindingValidationResult) -> str:
    if adapter.status != "completed":
        return "abstained"
    if validator.state == "verified" and adapter.disposition == "verified_finding":
        return "corroborated_synthetic_signal"
    if validator.state == "negative" and adapter.disposition == "negative_result":
        return "negative_synthetic_result"
    return "review_required"


def evaluate_offline_api_case(
    *,
    adapter: OfflineReferenceAdapter,
    case_id: str,
    invocation: AdapterInvocation,
    evidence: Sequence[EvidenceRecord],
) -> OfflineApiAssessmentResult:
    """Run the native adapter and validator over the same synthetic records."""

    _identifier(case_id, "case ID")
    if type(adapter) is not OfflineReferenceAdapter:
        raise OfflineApiAssessmentError("native reference adapter is required")
    if adapter.analyzer is not analyze_api_authorization:
        raise OfflineApiAssessmentError("API analyzer must be the native implementation")
    manifest = AdapterManifest.from_dict(adapter.manifest.to_dict())
    if manifest.profile_id != API_PROFILE_ID or manifest.reference_role != "api":
        raise OfflineApiAssessmentError("API reference profile is required")
    if not isinstance(invocation, AdapterInvocation):
        raise OfflineApiAssessmentError("typed adapter invocation is required")
    for value, label in (
        (invocation.invocation_id, "invocation ID"),
        (invocation.mission_id, "mission ID"),
        (invocation.target_id, "target ID"),
        (invocation.scope_id, "scope ID"),
    ):
        _identifier(value, label)
    ordered = _validate_evidence(evidence)
    if ordered and "source_receipt_sha256" in ordered[0].attributes:
        source = ordered[0].attributes
        if (
            source["source_scope_id"] != invocation.scope_id
            or source["source_target_id"] != invocation.target_id
        ):
            raise OfflineApiAssessmentError("receipt source and invocation context differ")
    expected_input = {"exchanges": _expected_exchanges(ordered)}
    if (
        not isinstance(invocation.input_data, Mapping)
        or dict(invocation.input_data) != expected_input
    ):
        raise OfflineApiAssessmentError("adapter input does not match typed evidence")
    try:
        adapter_result = adapter.execute(invocation)
    except QualificationError as exc:
        raise OfflineApiAssessmentError("synthetic adapter invocation was rejected") from exc
    try:
        validation_request = FindingValidationRequest(
            scope_id=invocation.scope_id,
            technique_id=API_TECHNIQUE_ID,
            validator_id=AuthorizationDifferentialValidator.descriptor.validator_id,
            validator_version=AuthorizationDifferentialValidator.descriptor.version,
            evidence=ordered,
            expected_evidence_hashes=tuple(record.evidence_sha256 for record in ordered),
        )
        validator_result = DEFAULT_REGISTRY.validate(validation_request)
    except FindingValidationError as exc:
        raise OfflineApiAssessmentError("typed evidence validation was rejected") from exc
    body = {
        "schema_version": 1,
        "case_id": case_id,
        "mission_id": invocation.mission_id,
        "target_id": invocation.target_id,
        "scope_id": invocation.scope_id,
        "invocation_id": invocation.invocation_id,
        "manifest_sha256": manifest.manifest_sha256,
        "adapter_result_sha256": adapter_result.result_sha256,
        "validator_result_sha256": validator_result.result_sha256,
        "evidence_sha256s": sorted(record.evidence_sha256 for record in ordered),
        "adapter_disposition": adapter_result.disposition,
        "validator_state": validator_result.state,
        "disposition": _disposition(adapter_result, validator_result),
        "effects": dict(NO_EFFECTS),
    }
    return OfflineApiAssessmentResult(
        schema_version=1,
        case_id=case_id,
        mission_id=invocation.mission_id,
        target_id=invocation.target_id,
        scope_id=invocation.scope_id,
        invocation_id=invocation.invocation_id,
        manifest_sha256=manifest.manifest_sha256,
        adapter_result_sha256=adapter_result.result_sha256,
        validator_result_sha256=validator_result.result_sha256,
        evidence_sha256s=tuple(body["evidence_sha256s"]),
        adapter_disposition=adapter_result.disposition,
        validator_state=validator_result.state,
        disposition=body["disposition"],
        result_sha256=_digest({"domain": RESULT_DOMAIN, "result": body}),
    )


def verify_offline_api_case(
    *,
    adapter: OfflineReferenceAdapter,
    case_id: str,
    invocation: AdapterInvocation,
    evidence: Sequence[EvidenceRecord],
    result: Mapping[str, Any],
) -> OfflineApiAssessmentResult:
    """Reproduce with the current exact rule and reject any changed result field."""

    expected = evaluate_offline_api_case(
        adapter=adapter, case_id=case_id, invocation=invocation, evidence=evidence
    )
    if not _same_json(result, expected.to_dict()):
        raise OfflineApiAssessmentError("offline API assessment does not match source evidence")
    return expected


def compare_offline_api_retest(
    *,
    adapter: OfflineReferenceAdapter,
    prior_case_id: str,
    prior_invocation: AdapterInvocation,
    prior_evidence: Sequence[EvidenceRecord],
    prior_result: Mapping[str, Any],
    second_case_id: str,
    second_invocation: AdapterInvocation,
    second_evidence: Sequence[EvidenceRecord],
    second_result: Mapping[str, Any],
) -> OfflineApiRetestResult:
    """Compare two reproduced synthetic cases without asserting chronology or a fix."""

    prior = verify_offline_api_case(
        adapter=adapter,
        case_id=prior_case_id,
        invocation=prior_invocation,
        evidence=prior_evidence,
        result=prior_result,
    )
    second = verify_offline_api_case(
        adapter=adapter,
        case_id=second_case_id,
        invocation=second_invocation,
        evidence=second_evidence,
        result=second_result,
    )
    if (
        prior.case_id == second.case_id
        or prior.invocation_id == second.invocation_id
        or prior.evidence_sha256s == second.evidence_sha256s
    ):
        raise OfflineApiAssessmentError("retest requires distinct case, invocation, and evidence")
    _validate_cross_case_sources(
        (_validate_evidence(prior_evidence), _validate_evidence(second_evidence))
    )
    if (
        prior.mission_id != second.mission_id
        or prior.target_id != second.target_id
        or prior.scope_id != second.scope_id
        or prior.manifest_sha256 != second.manifest_sha256
    ):
        raise OfflineApiAssessmentError("retest mission, target, scope, or adapter changed")
    prior_bindings = {
        (record.attributes["object_id"], record.attributes["action"]) for record in prior_evidence
    }
    second_bindings = {
        (record.attributes["object_id"], record.attributes["action"]) for record in second_evidence
    }
    if len(prior_bindings) != 1 or prior_bindings != second_bindings:
        raise OfflineApiAssessmentError("retest object or action binding is ambiguous")
    expectation_maps: list[dict[str, bool]] = []
    for records in (prior_evidence, second_evidence):
        expectations: dict[str, bool] = {}
        for record in records:
            principal = record.attributes["principal_id"]
            expected_access = record.attributes["expected_access"]
            if principal in expectations and expectations[principal] is not expected_access:
                raise OfflineApiAssessmentError(
                    "retest has conflicting expected access for one principal"
                )
            expectations[principal] = expected_access
        expectation_maps.append(expectations)
    if expectation_maps[0] != expectation_maps[1]:
        raise OfflineApiAssessmentError("retest principal or expected access changed")
    binding_sha256 = _digest(
        {
            "mission_id": prior.mission_id,
            "target_id": prior.target_id,
            "scope_id": prior.scope_id,
            "object_action": list(next(iter(prior_bindings))),
        }
    )
    if (
        prior.disposition == "corroborated_synthetic_signal"
        and second.disposition == "negative_synthetic_result"
    ):
        change = "prior_signal_not_observed_in_second_synthetic_case"
    elif (
        prior.disposition == "negative_synthetic_result"
        and second.disposition == "corroborated_synthetic_signal"
    ):
        change = "signal_observed_in_second_synthetic_case"
    else:
        change = "no_conclusive_synthetic_transition"
    body = {
        "schema_version": 1,
        "prior_result_sha256": prior.result_sha256,
        "second_result_sha256": second.result_sha256,
        "binding_sha256": binding_sha256,
        "observation_change": change,
        "effects": dict(NO_EFFECTS),
    }
    return OfflineApiRetestResult(
        schema_version=1,
        prior_result_sha256=prior.result_sha256,
        second_result_sha256=second.result_sha256,
        binding_sha256=binding_sha256,
        observation_change=change,
        result_sha256=_digest({"domain": RETEST_DOMAIN, "result": body}),
    )


def verify_offline_api_retest(
    *,
    result: Mapping[str, Any],
    adapter: OfflineReferenceAdapter,
    prior_case_id: str,
    prior_invocation: AdapterInvocation,
    prior_evidence: Sequence[EvidenceRecord],
    prior_result: Mapping[str, Any],
    second_case_id: str,
    second_invocation: AdapterInvocation,
    second_evidence: Sequence[EvidenceRecord],
    second_result: Mapping[str, Any],
) -> OfflineApiRetestResult:
    """Reproduce both source cases and the exact synthetic comparison."""

    expected = compare_offline_api_retest(
        adapter=adapter,
        prior_case_id=prior_case_id,
        prior_invocation=prior_invocation,
        prior_evidence=prior_evidence,
        prior_result=prior_result,
        second_case_id=second_case_id,
        second_invocation=second_invocation,
        second_evidence=second_evidence,
        second_result=second_result,
    )
    if not _same_json(result, expected.to_dict()):
        raise OfflineApiAssessmentError("offline API retest does not match source cases")
    return expected


def build_offline_api_batch(
    *, adapter: OfflineReferenceAdapter, sources: Sequence[OfflineApiCaseSource]
) -> OfflineApiAssessmentBatch:
    """Reproduce synthetic cases and make an effect-free assessment rollup."""

    if not isinstance(sources, (list, tuple)) or not 1 <= len(sources) <= 64:
        raise OfflineApiAssessmentError("one to 64 synthetic cases are required")
    if any(type(source) is not OfflineApiCaseSource for source in sources):
        raise OfflineApiAssessmentError("typed synthetic case sources are required")
    cases: list[dict[str, Any]] = []
    all_evidence_hashes: list[str] = []
    all_invocation_ids: list[str] = []
    binding_dispositions: dict[str, set[str]] = {}
    mission_ids: set[str] = set()
    scope_ids: set[str] = set()
    manifest_hashes: set[str] = set()
    source_record_sets: list[tuple[EvidenceRecord, ...]] = []
    for source in sources:
        records = _validate_evidence(source.evidence)
        source_record_sets.append(records)
        checked = verify_offline_api_case(
            adapter=adapter,
            case_id=source.case_id,
            invocation=source.invocation,
            evidence=records,
            result=source.result,
        )
        all_evidence_hashes.extend(checked.evidence_sha256s)
        all_invocation_ids.append(checked.invocation_id)
        mission_ids.add(checked.mission_id)
        scope_ids.add(checked.scope_id)
        manifest_hashes.add(checked.manifest_sha256)
        bindings = {
            (record.attributes["object_id"], record.attributes["action"]) for record in records
        }
        binding_hash: str | None = None
        if len(bindings) == 1:
            binding_hash = _digest(
                {
                    "mission_id": checked.mission_id,
                    "target_id": checked.target_id,
                    "scope_id": checked.scope_id,
                    "object_action": list(next(iter(bindings))),
                }
            )
            binding_dispositions.setdefault(binding_hash, set()).add(checked.disposition)
        cases.append(
            {
                "case_id": checked.case_id,
                "target_id": checked.target_id,
                "result_sha256": checked.result_sha256,
                "disposition": checked.disposition,
                "binding_sha256": binding_hash,
            }
        )
    if len(mission_ids) != 1 or len(scope_ids) != 1 or len(manifest_hashes) != 1:
        raise OfflineApiAssessmentError("batch mission, scope, or adapter changed")
    _validate_cross_case_sources(source_record_sets)
    if (
        len({case["case_id"] for case in cases}) != len(cases)
        or len(set(all_invocation_ids)) != len(all_invocation_ids)
        or len(set(all_evidence_hashes)) != len(all_evidence_hashes)
    ):
        raise OfflineApiAssessmentError("batch case, invocation, or evidence replay detected")
    ordered = tuple(sorted(cases, key=lambda case: case["case_id"]))
    counts = {
        disposition: sum(case["disposition"] == disposition for case in ordered)
        for disposition in (
            "corroborated_synthetic_signal",
            "negative_synthetic_result",
            "review_required",
            "abstained",
        )
    }
    review_ids = tuple(
        case["case_id"] for case in ordered if case["disposition"] != "negative_synthetic_result"
    )
    mixed = tuple(
        sorted(
            binding
            for binding, dispositions in binding_dispositions.items()
            if len(dispositions) > 1
        )
    )
    body = {
        "schema_version": 1,
        "mission_id": next(iter(mission_ids)),
        "scope_id": next(iter(scope_ids)),
        "manifest_sha256": next(iter(manifest_hashes)),
        "cases": list(ordered),
        "disposition_counts": counts,
        "review_candidate_case_ids": list(review_ids),
        "mixed_observation_binding_sha256s": list(mixed),
        "effects": dict(NO_EFFECTS),
    }
    return OfflineApiAssessmentBatch(
        schema_version=1,
        mission_id=body["mission_id"],
        scope_id=body["scope_id"],
        manifest_sha256=body["manifest_sha256"],
        cases=tuple(OfflineApiBatchCase(**case) for case in ordered),
        disposition_counts=tuple(counts.items()),
        review_candidate_case_ids=review_ids,
        mixed_observation_binding_sha256s=mixed,
        batch_sha256=_digest({"domain": BATCH_DOMAIN, "batch": body}),
    )


def verify_offline_api_batch(
    *,
    adapter: OfflineReferenceAdapter,
    sources: Sequence[OfflineApiCaseSource],
    batch: Mapping[str, Any],
) -> OfflineApiAssessmentBatch:
    """Reproduce every case and compare the complete assessment rollup."""

    expected = build_offline_api_batch(adapter=adapter, sources=sources)
    if not _same_json(batch, expected.to_dict()):
        raise OfflineApiAssessmentError("offline API batch does not match source cases")
    return expected


__all__ = [
    "OfflineApiAssessmentError",
    "OfflineApiAssessmentBatch",
    "OfflineApiAssessmentResult",
    "OfflineApiBatchCase",
    "OfflineApiCaseSource",
    "OfflineApiRetestResult",
    "build_offline_api_batch",
    "compare_offline_api_retest",
    "evaluate_offline_api_case",
    "verify_offline_api_case",
    "verify_offline_api_batch",
    "verify_offline_api_retest",
]
