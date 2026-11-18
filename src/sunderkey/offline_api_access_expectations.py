"""Bind synthetic API evidence labels to separate access expectations."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .offline_api_assessment import (
    OfflineApiAssessmentError,
    OfflineApiCaseSource,
    compare_offline_api_retest,
    verify_offline_api_case,
)
from .reference_adapters import OfflineReferenceAdapter

EXPECTATION_DOMAIN = "sunderkey.offline-api-access-expectations.v1"
BINDING_DOMAIN = "sunderkey.offline-api-expectation-binding.v1"
RETEST_BINDING_DOMAIN = "sunderkey.offline-api-retest-expectation-binding.v1"
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
NO_EFFECTS = {
    "authorization": "none",
    "credential_resolution": "none",
    "execution": "none",
    "finding_publication": "none",
    "network": "none",
    "qualification": "none",
    "target_interaction": "none",
}


class OfflineApiAccessExpectationError(ValueError):
    """Raised when an access assertion or its evidence binding is invalid."""


def _canonical(value: Any) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise OfflineApiAccessExpectationError("expectation input is not JSON data") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise OfflineApiAccessExpectationError(f"{label} is not an opaque identifier")
    return value


def build_offline_api_access_expectations(
    *,
    expectation_id: str,
    mission_id: str,
    target_id: str,
    scope_id: str,
    object_id: str,
    action: str,
    principal_expectations: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Content-address caller assertions without authenticating their source."""

    identifiers = {
        name: _identifier(value, name)
        for name, value in (
            ("expectation_id", expectation_id),
            ("mission_id", mission_id),
            ("target_id", target_id),
            ("scope_id", scope_id),
            ("object_id", object_id),
            ("action", action),
        )
    }
    if not isinstance(principal_expectations, (list, tuple)) or not (
        1 <= len(principal_expectations) <= 64
    ):
        raise OfflineApiAccessExpectationError("principal expectation count is invalid")
    entries = []
    for item in principal_expectations:
        if not isinstance(item, Mapping) or set(item) != {
            "principal_id", "expected_access"
        }:
            raise OfflineApiAccessExpectationError("principal expectation fields are invalid")
        if type(item["expected_access"]) is not bool:
            raise OfflineApiAccessExpectationError("expected_access must be boolean")
        entries.append({
            "principal_id": _identifier(item["principal_id"], "principal_id"),
            "expected_access": item["expected_access"],
        })
    principal_ids = [entry["principal_id"] for entry in entries]
    if principal_ids != sorted(set(principal_ids)):
        raise OfflineApiAccessExpectationError("principals must be sorted and unique")
    body = {
        "schema_version": 1,
        **identifiers,
        "principal_expectations": entries,
        "assertion_assurance": "caller_supplied_unsigned",
        "pre_observation_commitment_verified": False,
        "target_authorization_verified": False,
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }
    return {
        **body,
        "expectations_sha256": _digest({"domain": EXPECTATION_DOMAIN, "body": body}),
    }


def verify_offline_api_access_expectations(document: Mapping[str, Any]) -> dict[str, Any]:
    """Reject changed fields, noncanonical principal ordering, and digest drift."""

    if not isinstance(document, Mapping) or set(document) != {
        "schema_version", "expectation_id", "mission_id", "target_id", "scope_id",
        "object_id", "action", "principal_expectations", "assertion_assurance",
        "pre_observation_commitment_verified", "target_authorization_verified",
        "positive_use_approved", "effects", "expectations_sha256",
    }:
        raise OfflineApiAccessExpectationError("expectation document fields are invalid")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise OfflineApiAccessExpectationError("expectation schema version is invalid")
    expected = build_offline_api_access_expectations(
        expectation_id=document["expectation_id"],
        mission_id=document["mission_id"],
        target_id=document["target_id"],
        scope_id=document["scope_id"],
        object_id=document["object_id"],
        action=document["action"],
        principal_expectations=document["principal_expectations"],
    )
    if _canonical(document) != _canonical(expected):
        raise OfflineApiAccessExpectationError("expectation document does not match source")
    return expected


def bind_offline_api_case_to_access_expectations(
    *,
    adapter: OfflineReferenceAdapter,
    source: OfflineApiCaseSource,
    expectations: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay a case and check every evidence label against a separate assertion."""

    if type(source) is not OfflineApiCaseSource:
        raise OfflineApiAccessExpectationError("typed API case source is required")
    checked_expectations = verify_offline_api_access_expectations(expectations)
    try:
        case = verify_offline_api_case(
            adapter=adapter,
            case_id=source.case_id,
            invocation=source.invocation,
            evidence=source.evidence,
            result=source.result,
        )
    except OfflineApiAssessmentError as exc:
        raise OfflineApiAccessExpectationError("API case source replay failed") from exc
    for key in ("mission_id", "target_id", "scope_id"):
        if getattr(case, key) != checked_expectations[key]:
            raise OfflineApiAccessExpectationError("case and expectation context differ")
    expected_by_principal = {
        item["principal_id"]: item["expected_access"]
        for item in checked_expectations["principal_expectations"]
    }
    observed_by_principal: dict[str, bool] = {}
    for record in source.evidence:
        attributes = record.attributes
        if (
            attributes["object_id"] != checked_expectations["object_id"]
            or attributes["action"] != checked_expectations["action"]
        ):
            raise OfflineApiAccessExpectationError("evidence object or action differs")
        principal = attributes["principal_id"]
        if principal not in expected_by_principal:
            raise OfflineApiAccessExpectationError("evidence principal is not declared")
        expected_access = expected_by_principal[principal]
        if attributes["expected_access"] is not expected_access:
            raise OfflineApiAccessExpectationError("evidence expected_access differs")
        observed_by_principal[principal] = expected_access
    if set(observed_by_principal) != set(expected_by_principal):
        raise OfflineApiAccessExpectationError("declared principal has no evidence")
    body = {
        "schema_version": 1,
        "case_id": case.case_id,
        "case_result_sha256": case.result_sha256,
        "expectations_sha256": checked_expectations["expectations_sha256"],
        "evidence_sha256s": list(case.evidence_sha256s),
        "principal_count": len(expected_by_principal),
        "binding_status": "caller_assertions_match_replayed_evidence",
        "assertion_assurance": "caller_supplied_unsigned",
        "pre_observation_commitment_verified": False,
        "target_authorization_verified": False,
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "binding_sha256": _digest({"domain": BINDING_DOMAIN, "body": body})}


def verify_offline_api_access_expectation_binding(
    *,
    adapter: OfflineReferenceAdapter,
    source: OfflineApiCaseSource,
    expectations: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    expected = bind_offline_api_case_to_access_expectations(
        adapter=adapter, source=source, expectations=expectations
    )
    if not isinstance(binding, Mapping) or _canonical(binding) != _canonical(expected):
        raise OfflineApiAccessExpectationError("access expectation binding does not match")
    return expected


def bind_offline_api_retest_to_access_expectations(
    *,
    adapter: OfflineReferenceAdapter,
    prior_source: OfflineApiCaseSource,
    second_source: OfflineApiCaseSource,
    expectations: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind two reproduced cases and their comparison to one assertion set."""

    if (
        type(prior_source) is not OfflineApiCaseSource
        or type(second_source) is not OfflineApiCaseSource
    ):
        raise OfflineApiAccessExpectationError("typed API case sources are required")
    prior_binding = bind_offline_api_case_to_access_expectations(
        adapter=adapter, source=prior_source, expectations=expectations
    )
    second_binding = bind_offline_api_case_to_access_expectations(
        adapter=adapter, source=second_source, expectations=expectations
    )
    try:
        comparison = compare_offline_api_retest(
            adapter=adapter,
            prior_case_id=prior_source.case_id,
            prior_invocation=prior_source.invocation,
            prior_evidence=prior_source.evidence,
            prior_result=prior_source.result,
            second_case_id=second_source.case_id,
            second_invocation=second_source.invocation,
            second_evidence=second_source.evidence,
            second_result=second_source.result,
        )
    except OfflineApiAssessmentError as exc:
        raise OfflineApiAccessExpectationError("API retest comparison failed") from exc
    body = {
        "schema_version": 1,
        "expectations_sha256": prior_binding["expectations_sha256"],
        "prior_binding_sha256": prior_binding["binding_sha256"],
        "second_binding_sha256": second_binding["binding_sha256"],
        "comparison_sha256": comparison.result_sha256,
        "observation_change": comparison.observation_change,
        "binding_status": "same_caller_assertions_match_both_replayed_cases",
        "assertion_assurance": "caller_supplied_unsigned",
        "pre_observation_commitment_verified": False,
        "target_authorization_verified": False,
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }
    return {
        **body,
        "binding_sha256": _digest({"domain": RETEST_BINDING_DOMAIN, "body": body}),
    }


def verify_offline_api_retest_expectation_binding(
    *,
    adapter: OfflineReferenceAdapter,
    prior_source: OfflineApiCaseSource,
    second_source: OfflineApiCaseSource,
    expectations: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    expected = bind_offline_api_retest_to_access_expectations(
        adapter=adapter,
        prior_source=prior_source,
        second_source=second_source,
        expectations=expectations,
    )
    if not isinstance(binding, Mapping) or _canonical(binding) != _canonical(expected):
        raise OfflineApiAccessExpectationError("retest expectation binding does not match")
    return expected


__all__ = [
    "OfflineApiAccessExpectationError",
    "bind_offline_api_case_to_access_expectations",
    "bind_offline_api_retest_to_access_expectations",
    "build_offline_api_access_expectations",
    "verify_offline_api_access_expectation_binding",
    "verify_offline_api_access_expectations",
    "verify_offline_api_retest_expectation_binding",
]
