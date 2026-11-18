"""Join a nonfinding API reviewer dossier to local signed access expectations."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from .candidate_adapter_sdk import AdapterInvocation, AdapterManifest
from .coverage_scheduler import SchedulingLimits
from .finding_validators import (
    HARD_MAX_EVIDENCE_BYTES,
    HARD_MAX_EVIDENCE_RECORDS,
    HARD_MAX_TOTAL_EVIDENCE_BYTES,
    EvidenceRecord,
)
from .offline_api_access_expectations import NO_EFFECTS as EXPECTATION_NO_EFFECTS
from .offline_api_assessment import (
    OfflineApiAssessmentError,
    OfflineApiCaseSource,
    verify_offline_api_case,
)
from .offline_api_expectation_attestation import NO_EFFECTS as SIGNED_NO_EFFECTS
from .offline_api_expectation_attestation import (
    OfflineAccessPolicyKeyBinding,
    OfflineApiExpectationAttestationError,
    verify_offline_api_signed_retest_expectation_binding,
)
from .offline_api_reviewer_dossier import NO_EFFECTS as DOSSIER_NO_EFFECTS
from .offline_api_reviewer_dossier import (
    OfflineApiReviewerDossierError,
    verify_offline_api_reviewer_dossier,
)
from .reference_adapters import OfflineReferenceAdapter, analyze_api_authorization
from .registry import (
    CountContract,
    DomainCommand,
    ExpertProfile,
    ExpertRegistry,
    ManeuverGroup,
    PolicyTemplate,
    ProfileQualificationRecord,
)
from .signed_scope_compiler import (
    MAX_DOCUMENT_BYTES as MAX_SCOPE_DOCUMENT_BYTES,
)
from .signed_scope_compiler import (
    SignedAssessmentScope,
    VerifiedAssessmentScope,
)
from .target_context import TargetContextBundle

DOMAIN = "sunderkey.offline-api-signed-expectation-dossier.v1"
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_REVIEW_TASKS = 1_000
MAX_OPTIONS_DEPTH = 64
MAX_OPTIONS_NODES = 100_000
MAX_OPTIONS_CONTAINER_ITEMS = 100_000
MAX_OPTIONS_SINGLE_STRING_BYTES = 1_000_000
MAX_OPTIONS_TOTAL_STRING_BYTES = 8_000_000
MAX_REGISTRY_ITEMS = 1_000
MAX_REGISTRY_NESTED_ITEMS = 100
DOSSIER_FIELDS = {
    "review_bridge",
    "transition",
    "review_bridge_options",
    "transition_options",
}
DOSSIER_DOCUMENT_FIELDS = {
    "schema_version",
    "tenant_id",
    "scope_sha256",
    "batch_sha256",
    "planning_bundle_sha256",
    "schedule_sha256",
    "review_handoff_sha256",
    "transition_sha256",
    "child_world_snapshot_sha256",
    "prior_case_id",
    "second_case_id",
    "prior_result_sha256",
    "second_result_sha256",
    "observation_change",
    "proposed_task_ids",
    "review_status",
    "finding_count",
    "finding_state",
    "report_state",
    "origin_authentication",
    "effects",
    "dossier_sha256",
}
SIGNED_BINDING_FIELDS = {
    "schema_version",
    "expectations_sha256",
    "attestation_sha256",
    "retest_binding_sha256",
    "prior_binding_sha256",
    "second_binding_sha256",
    "observation_change",
    "identity_assurance",
    "policy_authority_verified",
    "pre_observation_commitment_verified",
    "positive_use_approved",
    "effects",
    "binding_sha256",
}
EXPECTATION_FIELDS = {
    "schema_version",
    "expectation_id",
    "mission_id",
    "target_id",
    "scope_id",
    "object_id",
    "action",
    "principal_expectations",
    "assertion_assurance",
    "pre_observation_commitment_verified",
    "target_authorization_verified",
    "positive_use_approved",
    "effects",
    "expectations_sha256",
}
ATTESTATION_FIELDS = {
    "schema_version",
    "expectations_sha256",
    "mission_id",
    "target_id",
    "scope_id",
    "object_id",
    "action",
    "policy_owner_id",
    "key_id",
    "identity_assurance",
    "policy_authority_verified",
    "pre_observation_commitment_verified",
    "positive_use_approved",
    "effects",
    "signature_base64",
    "attestation_sha256",
}
EFFECT_BOUNDARY = {
    "module_direct_action_authority": "none",
    "module_direct_execution": "none",
    "module_direct_finding_publication": "none",
    "module_direct_network": "none",
    "module_direct_report_publication": "none",
    "adapter_analyzer_requirement": "native_api_analyzer_identity_checked",
}


class OfflineApiSignedExpectationDossierError(ValueError):
    """Raised when locally signed expectations do not join the reviewer dossier."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _native_shape(value: Any, fields: set[str]) -> bool:
    return (
        type(value) is dict
        and len(value) == len(fields)
        and all(type(key) is str for key in value)
        and set(value) == fields
    )


def _bounded_text(value: Any, *, limit: int = 256) -> bool:
    return type(value) is str and len(value) <= limit


def _sha256(value: Any) -> bool:
    return type(value) is str and SHA256_RE.fullmatch(value) is not None


def _effects(value: Any, expected: dict[str, str]) -> bool:
    return (
        _native_shape(value, set(expected))
        and all(type(item) is str and len(item) <= 128 for item in value.values())
        and value == expected
    )


def _preflight_direct_documents(
    dossier: Any,
    signed_retest_binding: Any,
    expectations: Any,
    attestation: Any,
) -> None:
    """Reject oversized or nested supplied documents before upstream replay."""

    if (
        not _native_shape(dossier, DOSSIER_DOCUMENT_FIELDS)
        or type(dossier["schema_version"]) is not int
        or dossier["schema_version"] != 1
        or type(dossier["finding_count"]) is not int
        or dossier["finding_count"] != 0
        or any(
            not _sha256(dossier[field])
            for field in (
                "scope_sha256",
                "batch_sha256",
                "planning_bundle_sha256",
                "schedule_sha256",
                "review_handoff_sha256",
                "transition_sha256",
                "child_world_snapshot_sha256",
                "prior_result_sha256",
                "second_result_sha256",
                "dossier_sha256",
            )
        )
        or any(
            not _bounded_text(dossier[field])
            for field in (
                "tenant_id",
                "prior_case_id",
                "second_case_id",
                "observation_change",
                "review_status",
                "finding_state",
                "report_state",
                "origin_authentication",
            )
        )
        or type(dossier["proposed_task_ids"]) is not list
        or len(dossier["proposed_task_ids"]) > MAX_REVIEW_TASKS
        or any(not _bounded_text(item) for item in dossier["proposed_task_ids"])
        or not _effects(dossier["effects"], DOSSIER_NO_EFFECTS)
    ):
        raise OfflineApiSignedExpectationDossierError("dossier document preflight failed")
    if (
        not _native_shape(signed_retest_binding, SIGNED_BINDING_FIELDS)
        or type(signed_retest_binding["schema_version"]) is not int
        or signed_retest_binding["schema_version"] != 1
        or any(
            not _sha256(signed_retest_binding[field])
            for field in (
                "expectations_sha256",
                "attestation_sha256",
                "retest_binding_sha256",
                "prior_binding_sha256",
                "second_binding_sha256",
                "binding_sha256",
            )
        )
        or not _bounded_text(signed_retest_binding["observation_change"])
        or not _bounded_text(signed_retest_binding["identity_assurance"])
        or any(
            type(signed_retest_binding[field]) is not bool or signed_retest_binding[field]
            for field in (
                "policy_authority_verified",
                "pre_observation_commitment_verified",
                "positive_use_approved",
            )
        )
        or not _effects(signed_retest_binding["effects"], SIGNED_NO_EFFECTS)
    ):
        raise OfflineApiSignedExpectationDossierError("signed retest preflight failed")
    if (
        not _native_shape(expectations, EXPECTATION_FIELDS)
        or type(expectations["schema_version"]) is not int
        or expectations["schema_version"] != 1
        or not _sha256(expectations["expectations_sha256"])
        or any(
            not _bounded_text(expectations[field])
            for field in (
                "expectation_id",
                "mission_id",
                "target_id",
                "scope_id",
                "object_id",
                "action",
                "assertion_assurance",
            )
        )
        or any(
            type(expectations[field]) is not bool or expectations[field]
            for field in (
                "pre_observation_commitment_verified",
                "target_authorization_verified",
                "positive_use_approved",
            )
        )
        or type(expectations["principal_expectations"]) is not list
        or not 1 <= len(expectations["principal_expectations"]) <= 64
        or any(
            not _native_shape(item, {"principal_id", "expected_access"})
            or not _bounded_text(item["principal_id"])
            or type(item["expected_access"]) is not bool
            for item in expectations["principal_expectations"]
        )
        or not _effects(expectations["effects"], EXPECTATION_NO_EFFECTS)
    ):
        raise OfflineApiSignedExpectationDossierError("expectation document preflight failed")
    if (
        not _native_shape(attestation, ATTESTATION_FIELDS)
        or type(attestation["schema_version"]) is not int
        or attestation["schema_version"] != 1
        or not _sha256(attestation["expectations_sha256"])
        or not _sha256(attestation["attestation_sha256"])
        or any(
            not _bounded_text(attestation[field])
            for field in (
                "mission_id",
                "target_id",
                "scope_id",
                "object_id",
                "action",
                "policy_owner_id",
                "key_id",
                "identity_assurance",
            )
        )
        or type(attestation["signature_base64"]) is not str
        or len(attestation["signature_base64"]) != 88
        or any(
            type(attestation[field]) is not bool or attestation[field]
            for field in (
                "policy_authority_verified",
                "pre_observation_commitment_verified",
                "positive_use_approved",
            )
        )
        or not _effects(attestation["effects"], SIGNED_NO_EFFECTS)
    ):
        raise OfflineApiSignedExpectationDossierError("attestation document preflight failed")


def _typed_json_document(raw: Any, *, limit: int) -> dict[str, Any]:
    if type(raw) is not str or len(raw) > limit:
        raise OfflineApiSignedExpectationDossierError("typed document exceeds byte limit")
    try:
        byte_size = len(raw.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise OfflineApiSignedExpectationDossierError("typed document is invalid") from exc
    if byte_size > limit:
        raise OfflineApiSignedExpectationDossierError("typed document exceeds byte limit")
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise OfflineApiSignedExpectationDossierError("typed document is invalid") from exc
    if type(parsed) is not dict:
        raise OfflineApiSignedExpectationDossierError("typed document is not an object")
    return parsed


def _registry_document(registry: ExpertRegistry) -> dict[str, Any]:
    for name, expected_type in (
        ("policies", PolicyTemplate),
        ("groups", ManeuverGroup),
        ("commands", DomainCommand),
        ("profiles", ExpertProfile),
    ):
        entries = getattr(registry, name)
        if (
            type(entries) is not tuple
            or len(entries) > MAX_REGISTRY_ITEMS
            or any(type(entry) is not expected_type for entry in entries)
        ):
            raise OfflineApiSignedExpectationDossierError("registry entries are invalid")
    if type(registry.count_contract) is not CountContract:
        raise OfflineApiSignedExpectationDossierError("registry count contract is invalid")
    for policy in registry.policies:
        if any(
            type(getattr(policy, name)) is not tuple
            or len(getattr(policy, name)) > MAX_REGISTRY_NESTED_ITEMS
            for name in ("may", "may_not", "stop_conditions")
        ):
            raise OfflineApiSignedExpectationDossierError("registry policy list is oversized")
    for profile in registry.profiles:
        if (
            type(profile.tags) is not tuple
            or len(profile.tags) > MAX_REGISTRY_NESTED_ITEMS
            or (
                profile.qualification is not None
                and type(profile.qualification) is not ProfileQualificationRecord
            )
        ):
            raise OfflineApiSignedExpectationDossierError("registry profile is invalid")
    for name, entries, field in (
        ("group", registry.groups, "command_ids"),
        ("command", registry.commands, "specialist_profile_ids"),
    ):
        if any(
            type(getattr(entry, field)) is not tuple
            or len(getattr(entry, field)) > MAX_REGISTRY_NESTED_ITEMS
            for entry in entries
        ):
            raise OfflineApiSignedExpectationDossierError(f"registry {name} list is oversized")
    try:
        return registry.to_dict()
    except (AttributeError, TypeError, ValueError, RecursionError) as exc:
        raise OfflineApiSignedExpectationDossierError("registry projection is invalid") from exc


def _preflight_dossier_options(options: dict[str, Any]) -> None:
    """Bound native options and serialized fields of known typed sources."""

    nodes = 0
    string_bytes = 0
    active: set[int] = set()
    stack: list[tuple[Any, int, bool, bool]] = [(options, 0, False, False)]
    while stack:
        item, depth, exiting, allow_proxy = stack.pop()
        if exiting:
            active.remove(id(item))
            continue
        nodes += 1
        if nodes > MAX_OPTIONS_NODES or depth > MAX_OPTIONS_DEPTH:
            raise OfflineApiSignedExpectationDossierError("dossier options exceed structure limit")
        if type(item) is OfflineApiCaseSource:
            invocation = item.invocation
            if (
                type(invocation) is not AdapterInvocation
                or type(item.evidence) is not tuple
                or len(item.evidence) > HARD_MAX_EVIDENCE_RECORDS
            ):
                raise OfflineApiSignedExpectationDossierError(
                    "dossier options contain an invalid case source"
                )
            evidence_bytes = 0
            for record in item.evidence:
                if type(record) is not EvidenceRecord or type(record.content) is not bytes:
                    raise OfflineApiSignedExpectationDossierError(
                        "dossier options contain invalid evidence"
                    )
                evidence_bytes += len(record.content)
                if (
                    len(record.content) > HARD_MAX_EVIDENCE_BYTES
                    or evidence_bytes > HARD_MAX_TOTAL_EVIDENCE_BYTES
                ):
                    raise OfflineApiSignedExpectationDossierError(
                        "dossier options exceed evidence byte limit"
                    )
                for part in (
                    record.evidence_id,
                    record.content_sha256,
                    record.media_type,
                    record.role,
                    record.status_code,
                    record.headers,
                    record.attributes,
                    record.evidence_sha256,
                ):
                    stack.append((part, depth + 1, False, True))
            for part in (
                item.case_id,
                item.result,
                invocation.invocation_id,
                invocation.mission_id,
                invocation.authority_ref,
                invocation.profile_id,
                invocation.vector_id,
                invocation.target_id,
                invocation.scope_id,
                invocation.action_tier,
                invocation.environment,
                invocation.dry_run,
                invocation.credential_refs,
                invocation.input_data,
            ):
                stack.append((part, depth + 1, False, True))
        elif type(item) is OfflineReferenceAdapter:
            if (
                item.analyzer is not analyze_api_authorization
                or type(item.manifest) is not AdapterManifest
            ):
                raise OfflineApiSignedExpectationDossierError(
                    "dossier options contain a nonnative adapter"
                )
            parsed = _typed_json_document(
                item.manifest.document_json, limit=MAX_SCOPE_DOCUMENT_BYTES
            )
            stack.append((parsed, depth + 1, False, False))
        elif type(item) is VerifiedAssessmentScope:
            if type(item.signed_scope) is not SignedAssessmentScope:
                raise OfflineApiSignedExpectationDossierError(
                    "dossier options contain an invalid scope"
                )
            parsed = _typed_json_document(
                item.signed_scope.document_json, limit=MAX_SCOPE_DOCUMENT_BYTES
            )
            for part in (parsed, item.verified_at, item.verification_key_sha256):
                stack.append((part, depth + 1, False, False))
        elif type(item) is TargetContextBundle:
            parsed = _typed_json_document(item.document_json, limit=MAX_OPTIONS_TOTAL_STRING_BYTES)
            for part in (
                parsed,
                item.bundle_id,
                item.bundle_sha256,
                item.mission_id,
                item.authority_ref,
                item.status,
            ):
                stack.append((part, depth + 1, False, False))
        elif type(item) is ExpertRegistry:
            stack.append((_registry_document(item), depth + 1, False, False))
        elif type(item) is SchedulingLimits:
            stack.append((item.to_dict(), depth + 1, False, False))
        elif type(item) in (dict, list, tuple) or (allow_proxy and type(item) is MappingProxyType):
            if id(item) in active or len(item) > MAX_OPTIONS_CONTAINER_ITEMS:
                raise OfflineApiSignedExpectationDossierError(
                    "dossier options contain an invalid container"
                )
            active.add(id(item))
            stack.append((item, depth, True, allow_proxy))
            if type(item) in (dict, MappingProxyType):
                for key, child in item.items():
                    if type(key) is not str:
                        raise OfflineApiSignedExpectationDossierError(
                            "dossier options contain a nonnative key"
                        )
                    stack.append((key, depth + 1, False, allow_proxy))
                    stack.append((child, depth + 1, False, allow_proxy))
            else:
                stack.extend((child, depth + 1, False, allow_proxy) for child in item)
        elif isinstance(item, Mapping):
            raise OfflineApiSignedExpectationDossierError(
                "dossier options contain an unexpected mapping"
            )
        elif type(item) is str:
            if len(item) > MAX_OPTIONS_SINGLE_STRING_BYTES:
                raise OfflineApiSignedExpectationDossierError("dossier options exceed string limit")
            try:
                size = len(item.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise OfflineApiSignedExpectationDossierError(
                    "dossier options contain invalid text"
                ) from exc
            if size > MAX_OPTIONS_SINGLE_STRING_BYTES:
                raise OfflineApiSignedExpectationDossierError("dossier options exceed string limit")
            string_bytes += size
            if string_bytes > MAX_OPTIONS_TOTAL_STRING_BYTES:
                raise OfflineApiSignedExpectationDossierError(
                    "dossier options exceed total string limit"
                )
        elif type(item) is int:
            if item.bit_length() > 64:
                raise OfflineApiSignedExpectationDossierError(
                    "dossier options contain an oversized integer"
                )
        elif type(item) is float:
            if not math.isfinite(item):
                raise OfflineApiSignedExpectationDossierError(
                    "dossier options contain a nonfinite number"
                )
        elif type(item) is bool or item is None:
            continue
        else:
            raise OfflineApiSignedExpectationDossierError(
                "dossier options contain an unexpected value"
            )


def _case_result(adapter: Any, source: OfflineApiCaseSource) -> Any:
    if type(source) is not OfflineApiCaseSource:
        raise OfflineApiSignedExpectationDossierError("typed API case source is required")
    return verify_offline_api_case(
        adapter=adapter,
        case_id=source.case_id,
        invocation=source.invocation,
        evidence=source.evidence,
        result=source.result,
    )


def _same_native_companion(document: Any, expected: dict[str, Any]) -> bool:
    """Compare the shallow fixed schema without serializing arbitrary input."""

    if (
        type(document) is not dict
        or len(document) != len(expected)
        or any(type(key) is not str for key in document)
        or set(document) != set(expected)
    ):
        return False
    for key, expected_value in expected.items():
        actual = document[key]
        if type(actual) is not type(expected_value):
            return False
        if type(actual) is str:
            if len(actual) > 512 or actual != expected_value:
                return False
        elif type(actual) is dict:
            if (
                len(actual) != len(expected_value)
                or any(type(item) is not str for item in actual)
                or set(actual) != set(expected_value)
            ):
                return False
            for effect_key, effect_value in expected_value.items():
                supplied = actual[effect_key]
                if type(supplied) is not str or len(supplied) > 128 or supplied != effect_value:
                    return False
        elif actual != expected_value:
            return False
    return True


def build_offline_api_signed_expectation_dossier(
    *,
    dossier: Mapping[str, Any],
    dossier_options: Mapping[str, Any],
    signed_retest_binding: Mapping[str, Any],
    expectations: Mapping[str, Any],
    attestation: Mapping[str, Any],
    policy_key_binding: OfflineAccessPolicyKeyBinding,
    expected_tenant_id: str,
) -> dict[str, Any]:
    """Replay one dossier and signed policy assertion without approving use."""

    if type(expected_tenant_id) is not str or IDENTIFIER_RE.fullmatch(expected_tenant_id) is None:
        raise OfflineApiSignedExpectationDossierError("expected tenant is invalid")
    if (
        type(dossier_options) is not dict
        or len(dossier_options) != len(DOSSIER_FIELDS)
        or set(dossier_options) != DOSSIER_FIELDS
    ):
        raise OfflineApiSignedExpectationDossierError("dossier replay options are invalid")
    _preflight_direct_documents(dossier, signed_retest_binding, expectations, attestation)
    _preflight_dossier_options(dossier_options)
    try:
        transition_options = dossier_options["transition_options"]
        bridge_options = dossier_options["review_bridge_options"]
        if type(transition_options) is not dict or type(bridge_options) is not dict:
            raise OfflineApiSignedExpectationDossierError("dossier replay options are invalid")
        adapter = transition_options["adapter"]
        prior_source = transition_options["prior_source"]
        second_source = transition_options["second_source"]
        prior_entry = _case_result(adapter, prior_source)
        second_entry = _case_result(adapter, second_source)
        reviewed = verify_offline_api_reviewer_dossier(document=dossier, **dossier_options)
        signed = verify_offline_api_signed_retest_expectation_binding(
            adapter=adapter,
            prior_source=prior_source,
            second_source=second_source,
            expectations=expectations,
            attestation=attestation,
            binding=policy_key_binding,
            document=signed_retest_binding,
        )
        prior_exit = _case_result(adapter, prior_source)
        second_exit = _case_result(adapter, second_source)
        scope = bridge_options["planning_options"]["scope"]
        if (
            prior_entry != prior_exit
            or second_entry != second_exit
            or reviewed["tenant_id"] != expected_tenant_id
            or reviewed["prior_case_id"] != prior_entry.case_id
            or reviewed["second_case_id"] != second_entry.case_id
            or reviewed["prior_result_sha256"] != prior_entry.result_sha256
            or reviewed["second_result_sha256"] != second_entry.result_sha256
            or reviewed["observation_change"] != signed["observation_change"]
            or expectations["scope_id"] != scope.scope_id
            or prior_entry.scope_id != scope.scope_id
            or second_entry.scope_id != scope.scope_id
            or reviewed["scope_sha256"] != scope.content_sha256
        ):
            raise OfflineApiSignedExpectationDossierError(
                "dossier and signed expectation lineage differ"
            )
    except OfflineApiSignedExpectationDossierError:
        raise
    except (
        OfflineApiAssessmentError,
        OfflineApiExpectationAttestationError,
        OfflineApiReviewerDossierError,
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise OfflineApiSignedExpectationDossierError(
            "dossier or signed expectation originals are invalid"
        ) from exc

    body = {
        "schema_version": 1,
        "tenant_sha256": _digest({"tenant_id": expected_tenant_id}),
        "dossier_sha256": reviewed["dossier_sha256"],
        "signed_retest_binding_sha256": signed["binding_sha256"],
        "expectations_sha256": signed["expectations_sha256"],
        "attestation_sha256": signed["attestation_sha256"],
        "scope_id_sha256": _digest({"scope_id": scope.scope_id}),
        "review_scope_sha256": reviewed["scope_sha256"],
        "prior_case_id_sha256": _digest({"case_id": prior_entry.case_id}),
        "second_case_id_sha256": _digest({"case_id": second_entry.case_id}),
        "prior_result_sha256": prior_entry.result_sha256,
        "second_result_sha256": second_entry.result_sha256,
        "observation_change": reviewed["observation_change"],
        "review_status": "awaiting_independent_human_review",
        "signature_assurance": "caller_pinned_local_key_only",
        "signed_scope_id_binding_verified": True,
        "signed_scope_digest_binding_verified": False,
        "policy_owner_authority_verified": False,
        "pre_observation_commitment_verified": False,
        "finding_verified": False,
        "finding_publication_verified": False,
        "report_publication_verified": False,
        "positive_use_approved": False,
        "effects": dict(EFFECT_BOUNDARY),
    }
    return {**body, "companion_sha256": _digest({"domain": DOMAIN, "body": body})}


def verify_offline_api_signed_expectation_dossier(
    *,
    document: Mapping[str, Any],
    dossier: Mapping[str, Any],
    dossier_options: Mapping[str, Any],
    signed_retest_binding: Mapping[str, Any],
    expectations: Mapping[str, Any],
    attestation: Mapping[str, Any],
    policy_key_binding: OfflineAccessPolicyKeyBinding,
    expected_tenant_id: str,
) -> dict[str, Any]:
    """Rebuild a saved companion from the same exact original inputs."""

    expected = build_offline_api_signed_expectation_dossier(
        dossier=dossier,
        dossier_options=dossier_options,
        signed_retest_binding=signed_retest_binding,
        expectations=expectations,
        attestation=attestation,
        policy_key_binding=policy_key_binding,
        expected_tenant_id=expected_tenant_id,
    )
    if not _same_native_companion(document, expected):
        raise OfflineApiSignedExpectationDossierError(
            "signed expectation dossier does not match originals"
        )
    return expected


__all__ = [
    "OfflineApiSignedExpectationDossierError",
    "build_offline_api_signed_expectation_dossier",
    "verify_offline_api_signed_expectation_dossier",
]
