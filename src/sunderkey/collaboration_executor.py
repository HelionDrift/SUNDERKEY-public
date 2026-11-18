"""Provider-neutral execution adapter contracts for fenced worker sessions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Protocol

from .collaboration import CollaborationPlan
from .collaboration_execution_session_authority import (
    CollaborationExecutionSessionAuthority,
)
from .collaboration_execution_session_status import (
    CollaborationExecutionSessionAuthorityStatus,
)
from .collaboration_ownership_chain import (
    collaboration_work_item_objective_sha256,
)
from .errors import CollaborationPlanError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .store import parse_timestamp
from .validation import is_ascii_text

SCHEMA_VERSION = 1
DISPATCH_DOMAIN = "sunderkey.collaboration-executor-dispatch.v1"
ACKNOWLEDGEMENT_DOMAIN = "sunderkey.collaboration-executor-acknowledgement.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
OPERATIONS = (
    "start",
    "action",
    "evidence",
    "heartbeat",
    "pause",
    "resume",
    "stop",
    "destroy",
)
SAFETY_REDUCING_OPERATIONS = ("pause", "stop", "destroy")
SAFETY_REDUCTION_GRACE_SECONDS = 300
ACKNOWLEDGEMENT_OUTCOMES = ("accepted", "rejected", "failed")
PROVIDER_WORKER_STATES = (
    "ready",
    "active",
    "paused",
    "stopped",
    "destroyed",
    "unchanged",
    "rejected",
    "failed",
    "unavailable",
)
ACCEPTED_STATES = {
    "start": {"ready"},
    "action": {"active"},
    "evidence": {"active", "paused", "stopped", "unchanged"},
    "heartbeat": {"active", "paused", "stopped"},
    "pause": {"paused"},
    "resume": {"active"},
    "stop": {"stopped"},
    "destroy": {"destroyed"},
}


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _text(value: Any, label: str, *, maximum: int = 2048) -> str:
    if (
        not is_ascii_text(value)
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) > 126 for character in value)
    ):
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _binding(
    raw: Any,
    label: str,
    *,
    fields: set[str],
) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(value, fields, label)
    return dict(value)


def collaboration_executor_operation_input_sha256(operation_input: bytes) -> str:
    """Hash an exact opaque adapter input without interpreting its contents."""

    if not isinstance(operation_input, bytes):
        raise TypeError("operation_input must be bytes")
    return f"sha256:{hashlib.sha256(operation_input).hexdigest()}"


@dataclass(frozen=True)
class CollaborationExecutorDispatchEnvelope:
    """One content-addressed request for a provider-neutral adapter operation."""

    dispatch_id: str
    dispatch_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationExecutorDispatchEnvelope:
        value = _mapping(raw, "collaboration executor dispatch")
        fields = {
            "schema_version",
            "dispatch_id",
            "dispatch_sha256",
            "operation",
            "operation_sequence",
            "authority_status",
            "session_authority",
            "mission",
            "work_item",
            "worker",
            "session",
            "credential",
            "policy",
            "issued_at",
            "expires_at",
            "dispatch_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration executor dispatch")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Executor dispatch schema is invalid")
        dispatch_id = value.get("dispatch_id")
        dispatch_sha256 = value.get("dispatch_sha256")
        if (
            not isinstance(dispatch_id, str)
            or re.fullmatch(r"EXD-[0-9A-F]{32}", dispatch_id) is None
        ):
            raise CollaborationPlanError("Executor dispatch identity is invalid")
        _sha256(dispatch_sha256, "dispatch_sha256")
        operation = value.get("operation")
        if operation not in OPERATIONS:
            raise CollaborationPlanError("Executor dispatch operation is invalid")
        _positive_integer(value.get("operation_sequence"), "operation_sequence")

        status = _binding(
            value.get("authority_status"),
            "authority_status",
            fields={"status_id", "status_sha256", "observed_at"},
        )
        if (
            not isinstance(status["status_id"], str)
            or re.fullmatch(r"ESS-[0-9A-F]{32}", status["status_id"]) is None
        ):
            raise CollaborationPlanError("Executor dispatch status binding is invalid")
        _sha256(status["status_sha256"], "authority_status.status_sha256")
        observed = parse_timestamp(status["observed_at"], "authority_status.observed_at")

        authority = _binding(
            value.get("session_authority"),
            "session_authority",
            fields={"session_authority_id", "session_authority_sha256"},
        )
        if (
            not isinstance(authority["session_authority_id"], str)
            or re.fullmatch(
                r"ESA-[0-9A-F]{32}", authority["session_authority_id"]
            )
            is None
        ):
            raise CollaborationPlanError("Executor dispatch authority binding is invalid")
        _sha256(
            authority["session_authority_sha256"],
            "session_authority.session_authority_sha256",
        )

        mission = _binding(
            value.get("mission"),
            "mission",
            fields={
                "mission_id",
                "mission_sha256",
                "collaboration_plan_id",
                "collaboration_plan_sha256",
                "scope_reference",
            },
        )
        for field in ("mission_id", "collaboration_plan_id"):
            _identifier(mission[field], f"mission.{field}")
        _text(mission["scope_reference"], "mission.scope_reference")
        _sha256(mission["mission_sha256"], "mission.mission_sha256")
        _sha256(
            mission["collaboration_plan_sha256"],
            "mission.collaboration_plan_sha256",
        )

        work_item = _binding(
            value.get("work_item"),
            "work_item",
            fields={"work_item_id", "work_item_objective_sha256"},
        )
        _identifier(work_item["work_item_id"], "work_item.work_item_id")
        _sha256(
            work_item["work_item_objective_sha256"],
            "work_item.work_item_objective_sha256",
        )
        worker = _binding(
            value.get("worker"),
            "worker",
            fields={"worker_principal_id", "owner_epoch", "fence_generation"},
        )
        _identifier(worker["worker_principal_id"], "worker.worker_principal_id")
        _positive_integer(worker["owner_epoch"], "worker.owner_epoch")
        _positive_integer(worker["fence_generation"], "worker.fence_generation")
        session = _binding(
            value.get("session"),
            "session",
            fields={"session_id", "session_sha256"},
        )
        _identifier(session["session_id"], "session.session_id")
        _sha256(session["session_sha256"], "session.session_sha256")
        credential = _binding(
            value.get("credential"),
            "credential",
            fields={"credential_reference_id", "credential_sha256"},
        )
        _identifier(
            credential["credential_reference_id"],
            "credential.credential_reference_id",
        )
        _sha256(credential["credential_sha256"], "credential.credential_sha256")
        policy = _binding(
            value.get("policy"),
            "policy",
            fields={"tool_policy_sha256", "operation_input_sha256"},
        )
        _sha256(policy["tool_policy_sha256"], "policy.tool_policy_sha256")
        _sha256(
            policy["operation_input_sha256"],
            "policy.operation_input_sha256",
        )
        issued = parse_timestamp(value.get("issued_at"), "issued_at")
        expires = parse_timestamp(value.get("expires_at"), "expires_at")
        if issued < observed or expires <= issued:
            raise CollaborationPlanError("Executor dispatch time window is invalid")
        if (
            value.get("dispatch_status") != "prepared_provider_dispatch"
            or value.get("runtime_effect") != "none"
        ):
            raise CollaborationPlanError("Executor dispatch boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"dispatch_id", "dispatch_sha256"}
        }
        digest = _canonical_sha256({"domain": DISPATCH_DOMAIN, "dispatch": body})
        expected_id = "EXD-" + digest.removeprefix("sha256:")[:32].upper()
        if dispatch_sha256 != digest or dispatch_id != expected_id:
            raise CollaborationPlanError("Executor dispatch hash is invalid")
        return cls(dispatch_id, dispatch_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Executor dispatch is invalid")
        return value


@dataclass(frozen=True)
class CollaborationExecutorAcknowledgement:
    """Untrusted provider report bound to one exact dispatch and session fence."""

    acknowledgement_id: str
    acknowledgement_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationExecutorAcknowledgement:
        value = _mapping(raw, "collaboration executor acknowledgement")
        fields = {
            "schema_version",
            "acknowledgement_id",
            "acknowledgement_sha256",
            "dispatch",
            "provider",
            "worker",
            "session",
            "credential",
            "outcome",
            "provider_worker_state",
            "provider_evidence_sha256",
            "acknowledged_at",
            "authentication_status",
            "external_effect_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration executor acknowledgement")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Executor acknowledgement schema is invalid")
        acknowledgement_id = value.get("acknowledgement_id")
        acknowledgement_sha256 = value.get("acknowledgement_sha256")
        if (
            not isinstance(acknowledgement_id, str)
            or re.fullmatch(r"EXA-[0-9A-F]{32}", acknowledgement_id) is None
        ):
            raise CollaborationPlanError("Executor acknowledgement identity is invalid")
        _sha256(acknowledgement_sha256, "acknowledgement_sha256")
        dispatch = _binding(
            value.get("dispatch"),
            "dispatch",
            fields={
                "dispatch_id",
                "dispatch_sha256",
                "operation",
                "operation_sequence",
            },
        )
        if (
            not isinstance(dispatch["dispatch_id"], str)
            or re.fullmatch(r"EXD-[0-9A-F]{32}", dispatch["dispatch_id"]) is None
            or dispatch["operation"] not in OPERATIONS
        ):
            raise CollaborationPlanError("Executor acknowledgement dispatch is invalid")
        _sha256(dispatch["dispatch_sha256"], "dispatch.dispatch_sha256")
        _positive_integer(dispatch["operation_sequence"], "dispatch.operation_sequence")
        provider = _binding(
            value.get("provider"),
            "provider",
            fields={"adapter_id", "adapter_version", "adapter_build_sha256"},
        )
        _identifier(provider["adapter_id"], "provider.adapter_id")
        _identifier(provider["adapter_version"], "provider.adapter_version")
        _sha256(provider["adapter_build_sha256"], "provider.adapter_build_sha256")
        worker = _binding(
            value.get("worker"),
            "worker",
            fields={
                "worker_principal_id",
                "runtime_instance_id",
                "fence_generation",
            },
        )
        _identifier(worker["worker_principal_id"], "worker.worker_principal_id")
        _identifier(worker["runtime_instance_id"], "worker.runtime_instance_id")
        _positive_integer(worker["fence_generation"], "worker.fence_generation")
        session = _binding(
            value.get("session"),
            "session",
            fields={"session_id", "session_sha256"},
        )
        _identifier(session["session_id"], "session.session_id")
        _sha256(session["session_sha256"], "session.session_sha256")
        credential = _binding(
            value.get("credential"),
            "credential",
            fields={"credential_reference_id", "credential_sha256"},
        )
        _identifier(
            credential["credential_reference_id"],
            "credential.credential_reference_id",
        )
        _sha256(credential["credential_sha256"], "credential.credential_sha256")
        outcome = value.get("outcome")
        provider_state = value.get("provider_worker_state")
        if outcome not in ACKNOWLEDGEMENT_OUTCOMES:
            raise CollaborationPlanError("Executor acknowledgement outcome is invalid")
        if provider_state not in PROVIDER_WORKER_STATES:
            raise CollaborationPlanError("Executor provider worker state is invalid")
        operation = dispatch["operation"]
        if outcome == "accepted" and provider_state not in ACCEPTED_STATES[operation]:
            raise CollaborationPlanError("Executor accepted worker state is invalid")
        if outcome == "rejected" and provider_state != "rejected":
            raise CollaborationPlanError("Executor rejected worker state is invalid")
        if outcome == "failed" and provider_state not in {"failed", "unavailable"}:
            raise CollaborationPlanError("Executor failed worker state is invalid")
        _sha256(value.get("provider_evidence_sha256"), "provider_evidence_sha256")
        parse_timestamp(value.get("acknowledged_at"), "acknowledged_at")
        if (
            value.get("authentication_status") != "provider_assertion_unverified"
            or value.get("external_effect_status") != "provider_report_only"
            or value.get("runtime_effect") != "none"
        ):
            raise CollaborationPlanError("Executor acknowledgement boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"acknowledgement_id", "acknowledgement_sha256"}
        }
        digest = _canonical_sha256(
            {"domain": ACKNOWLEDGEMENT_DOMAIN, "acknowledgement": body}
        )
        expected_id = "EXA-" + digest.removeprefix("sha256:")[:32].upper()
        if acknowledgement_sha256 != digest or acknowledgement_id != expected_id:
            raise CollaborationPlanError("Executor acknowledgement hash is invalid")
        return cls(acknowledgement_id, acknowledgement_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Executor acknowledgement is invalid")
        return value


class CollaborationExecutorAdapter(Protocol):
    """External adapter interface. Implementations remain deployment-owned."""

    def start(
        self,
        dispatch: CollaborationExecutorDispatchEnvelope,
        operation_input: bytes,
    ) -> CollaborationExecutorAcknowledgement: ...

    def action(
        self,
        dispatch: CollaborationExecutorDispatchEnvelope,
        operation_input: bytes,
    ) -> CollaborationExecutorAcknowledgement: ...

    def evidence(
        self,
        dispatch: CollaborationExecutorDispatchEnvelope,
        operation_input: bytes,
    ) -> CollaborationExecutorAcknowledgement: ...

    def heartbeat(
        self,
        dispatch: CollaborationExecutorDispatchEnvelope,
        operation_input: bytes,
    ) -> CollaborationExecutorAcknowledgement: ...

    def pause(
        self,
        dispatch: CollaborationExecutorDispatchEnvelope,
        operation_input: bytes,
    ) -> CollaborationExecutorAcknowledgement: ...

    def resume(
        self,
        dispatch: CollaborationExecutorDispatchEnvelope,
        operation_input: bytes,
    ) -> CollaborationExecutorAcknowledgement: ...

    def stop(
        self,
        dispatch: CollaborationExecutorDispatchEnvelope,
        operation_input: bytes,
    ) -> CollaborationExecutorAcknowledgement: ...

    def destroy(
        self,
        dispatch: CollaborationExecutorDispatchEnvelope,
        operation_input: bytes,
    ) -> CollaborationExecutorAcknowledgement: ...


def build_collaboration_executor_dispatch(
    *,
    status: CollaborationExecutionSessionAuthorityStatus,
    authority: CollaborationExecutionSessionAuthority,
    collaboration_plan: CollaborationPlan,
    operation: str,
    operation_sequence: int,
    tool_policy_sha256: str,
    operation_input_sha256: str,
    issued_at: str,
    expires_at: str,
) -> CollaborationExecutorDispatchEnvelope:
    """Build a dispatch only from currently executor-available authority."""

    parsed_status = CollaborationExecutionSessionAuthorityStatus.from_dict(
        status.to_dict()
    )
    parsed_authority = CollaborationExecutionSessionAuthority.from_dict(
        authority.to_dict()
    )
    plan = CollaborationPlan.from_dict(collaboration_plan.to_dict())
    status_document = parsed_status.to_dict()
    authority_document = parsed_authority.to_dict()
    session = authority_document["session"]
    is_safety_reduction = operation in SAFETY_REDUCING_OPERATIONS
    ordinary_available = (
        status_document["control_plane_state"] == "available_for_executor"
        and status_document["revocation"] is None
    )
    safety_available = (
        is_safety_reduction
        and status_document["activation"] is not None
        and status_document["control_plane_state"]
        in {"available_for_executor", "expired", "revoked"}
    )
    if (
        (not ordinary_available and not safety_available)
        or status_document["external_worker_state"] != "unobserved"
        or status_document["runtime_effect"] != "none"
    ):
        raise CollaborationPlanError("Execution session is not available for dispatch")
    if status_document["session_authority"] != {
        "session_authority_id": parsed_authority.session_authority_id,
        "session_authority_sha256": parsed_authority.session_authority_sha256,
    }:
        raise CollaborationPlanError("Executor dispatch authority status is stale")
    if status_document["session"] != {
        "session_id": session["session_id"],
        "session_sha256": session["session_sha256"],
    } or status_document["credential"] != {
        "credential_reference_id": session["credential_reference_id"],
        "credential_sha256": session["credential_sha256"],
    }:
        raise CollaborationPlanError("Executor dispatch session status is stale")
    if (
        status_document["fence_generation"] != session["fence_generation"]
        or plan.plan_id != session["collaboration_plan_id"]
        or plan.content_sha256 != session["collaboration_plan_sha256"]
        or plan.mission_id != session["mission_id"]
    ):
        raise CollaborationPlanError("Executor dispatch plan or fence is stale")
    items = {item.work_item_id: item for item in plan.work_items}
    work_item = items.get(session["work_item_id"])
    if (
        work_item is None
        or collaboration_work_item_objective_sha256(work_item)
        != session["work_item_objective_sha256"]
        or work_item.owner_profile_id != session["worker_principal_id"]
    ):
        raise CollaborationPlanError("Executor dispatch work item is stale")
    selected_operation = operation if operation in OPERATIONS else None
    if selected_operation is None:
        raise CollaborationPlanError("Executor dispatch operation is invalid")
    sequence = _positive_integer(operation_sequence, "operation_sequence")
    tool_policy = _sha256(tool_policy_sha256, "tool_policy_sha256")
    input_sha256 = _sha256(operation_input_sha256, "operation_input_sha256")
    issued = parse_timestamp(issued_at, "issued_at")
    expires = parse_timestamp(expires_at, "expires_at")
    observed = parse_timestamp(status_document["observed_at"], "observed_at")
    effective = parse_timestamp(authority_document["effective_at"], "effective_at")
    authority_expires = parse_timestamp(authority_document["expires_at"], "authority_expires_at")
    dispatch_deadline = (
        authority_expires
        + timedelta(seconds=SAFETY_REDUCTION_GRACE_SECONDS)
        if is_safety_reduction
        else authority_expires
    )
    if (
        issued < observed
        or issued < effective
        or expires <= issued
        or expires > dispatch_deadline
    ):
        raise CollaborationPlanError("Executor dispatch exceeds session authority time")
    body = {
        "schema_version": SCHEMA_VERSION,
        "operation": selected_operation,
        "operation_sequence": sequence,
        "authority_status": {
            "status_id": parsed_status.status_id,
            "status_sha256": parsed_status.status_sha256,
            "observed_at": status_document["observed_at"],
        },
        "session_authority": {
            "session_authority_id": parsed_authority.session_authority_id,
            "session_authority_sha256": parsed_authority.session_authority_sha256,
        },
        "mission": {
            "mission_id": plan.mission_id,
            "mission_sha256": plan.mission_sha256,
            "collaboration_plan_id": plan.plan_id,
            "collaboration_plan_sha256": plan.content_sha256,
            "scope_reference": plan.scope_reference,
        },
        "work_item": {
            "work_item_id": work_item.work_item_id,
            "work_item_objective_sha256": session["work_item_objective_sha256"],
        },
        "worker": {
            "worker_principal_id": session["worker_principal_id"],
            "owner_epoch": session["owner_epoch"],
            "fence_generation": session["fence_generation"],
        },
        "session": {
            "session_id": session["session_id"],
            "session_sha256": session["session_sha256"],
        },
        "credential": {
            "credential_reference_id": session["credential_reference_id"],
            "credential_sha256": session["credential_sha256"],
        },
        "policy": {
            "tool_policy_sha256": tool_policy,
            "operation_input_sha256": input_sha256,
        },
        "issued_at": issued_at,
        "expires_at": expires_at,
        "dispatch_status": "prepared_provider_dispatch",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": DISPATCH_DOMAIN, "dispatch": body})
    return CollaborationExecutorDispatchEnvelope.from_dict(
        {
            **body,
            "dispatch_id": "EXD-" + digest.removeprefix("sha256:")[:32].upper(),
            "dispatch_sha256": digest,
        }
    )


def validate_collaboration_executor_operation_input(
    dispatch: CollaborationExecutorDispatchEnvelope,
    operation_input: bytes,
) -> None:
    """Fail closed when out-of-band operation bytes do not match the dispatch."""

    parsed = CollaborationExecutorDispatchEnvelope.from_dict(dispatch.to_dict())
    expected = parsed.to_dict()["policy"]["operation_input_sha256"]
    if collaboration_executor_operation_input_sha256(operation_input) != expected:
        raise CollaborationPlanError("Executor operation input hash is invalid")


def build_collaboration_executor_acknowledgement(
    dispatch: CollaborationExecutorDispatchEnvelope,
    *,
    adapter_id: str,
    adapter_version: str,
    adapter_build_sha256: str,
    runtime_instance_id: str,
    outcome: str,
    provider_worker_state: str,
    provider_evidence_sha256: str,
    acknowledged_at: str,
) -> CollaborationExecutorAcknowledgement:
    """Normalize an unverified provider report without claiming worker proof."""

    parsed = CollaborationExecutorDispatchEnvelope.from_dict(dispatch.to_dict())
    document = parsed.to_dict()
    acknowledged = parse_timestamp(acknowledged_at, "acknowledged_at")
    if acknowledged < parse_timestamp(document["issued_at"], "issued_at"):
        raise CollaborationPlanError("Executor acknowledgement precedes dispatch")
    body = {
        "schema_version": SCHEMA_VERSION,
        "dispatch": {
            "dispatch_id": parsed.dispatch_id,
            "dispatch_sha256": parsed.dispatch_sha256,
            "operation": document["operation"],
            "operation_sequence": document["operation_sequence"],
        },
        "provider": {
            "adapter_id": _identifier(adapter_id, "adapter_id"),
            "adapter_version": _identifier(adapter_version, "adapter_version"),
            "adapter_build_sha256": _sha256(
                adapter_build_sha256,
                "adapter_build_sha256",
            ),
        },
        "worker": {
            "worker_principal_id": document["worker"]["worker_principal_id"],
            "runtime_instance_id": _identifier(
                runtime_instance_id,
                "runtime_instance_id",
            ),
            "fence_generation": document["worker"]["fence_generation"],
        },
        "session": dict(document["session"]),
        "credential": dict(document["credential"]),
        "outcome": outcome,
        "provider_worker_state": provider_worker_state,
        "provider_evidence_sha256": _sha256(
            provider_evidence_sha256,
            "provider_evidence_sha256",
        ),
        "acknowledged_at": acknowledged_at,
        "authentication_status": "provider_assertion_unverified",
        "external_effect_status": "provider_report_only",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256(
        {"domain": ACKNOWLEDGEMENT_DOMAIN, "acknowledgement": body}
    )
    return CollaborationExecutorAcknowledgement.from_dict(
        {
            **body,
            "acknowledgement_id": "EXA-"
            + digest.removeprefix("sha256:")[:32].upper(),
            "acknowledgement_sha256": digest,
        }
    )


def validate_collaboration_executor_acknowledgement(
    dispatch: CollaborationExecutorDispatchEnvelope,
    acknowledgement: CollaborationExecutorAcknowledgement,
) -> CollaborationExecutorAcknowledgement:
    """Verify exact dispatch and fence bindings on an untrusted provider report."""

    parsed_dispatch = CollaborationExecutorDispatchEnvelope.from_dict(
        dispatch.to_dict()
    )
    parsed_acknowledgement = CollaborationExecutorAcknowledgement.from_dict(
        acknowledgement.to_dict()
    )
    request = parsed_dispatch.to_dict()
    report = parsed_acknowledgement.to_dict()
    if report["dispatch"] != {
        "dispatch_id": parsed_dispatch.dispatch_id,
        "dispatch_sha256": parsed_dispatch.dispatch_sha256,
        "operation": request["operation"],
        "operation_sequence": request["operation_sequence"],
    }:
        raise CollaborationPlanError("Executor acknowledgement dispatch is stale")
    if (
        report["session"] != request["session"]
        or report["credential"] != request["credential"]
        or report["worker"]["worker_principal_id"]
        != request["worker"]["worker_principal_id"]
        or report["worker"]["fence_generation"]
        != request["worker"]["fence_generation"]
    ):
        raise CollaborationPlanError("Executor acknowledgement fence is stale")
    if parse_timestamp(
        report["acknowledged_at"], "acknowledged_at"
    ) > parse_timestamp(request["expires_at"], "expires_at"):
        raise CollaborationPlanError("Executor acknowledgement is late")
    return parsed_acknowledgement


__all__ = [
    "ACKNOWLEDGEMENT_OUTCOMES",
    "OPERATIONS",
    "PROVIDER_WORKER_STATES",
    "SAFETY_REDUCING_OPERATIONS",
    "SAFETY_REDUCTION_GRACE_SECONDS",
    "CollaborationExecutorAcknowledgement",
    "CollaborationExecutorAdapter",
    "CollaborationExecutorDispatchEnvelope",
    "build_collaboration_executor_acknowledgement",
    "build_collaboration_executor_dispatch",
    "collaboration_executor_operation_input_sha256",
    "validate_collaboration_executor_acknowledgement",
    "validate_collaboration_executor_operation_input",
]
