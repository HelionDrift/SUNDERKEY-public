"""Authenticated principal credentials for the SUNDERKEY runtime."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import PrincipalAuthenticationError
from .events import (
    APPROVAL_ID_PATTERN,
    EVENT_ID_PATTERN,
    MISSION_ID_PATTERN,
    PROFILE_ID_PATTERN,
)
from .types import ActionTier, MissionEnvironment

TRUST_POLICY_SIGNING_DOMAIN = b"SUNDERKEY\x00PRINCIPAL-TRUST-POLICY\x00V1\x00"
SCOPE_GRANT_SIGNING_DOMAIN = b"SUNDERKEY\x00PRINCIPAL-SCOPE-GRANT\x00V1\x00"
SCOPE_GRANT_REVOCATION_SIGNING_DOMAIN = (
    b"SUNDERKEY\x00PRINCIPAL-SCOPE-GRANT-REVOCATION\x00V1\x00"
)
PRINCIPAL_ASSERTION_SIGNING_DOMAIN = b"SUNDERKEY\x00PRINCIPAL-ASSERTION\x00V1\x00"
OPERATION_INTENT_HASH_DOMAIN = b"SUNDERKEY\x00OPERATION-INTENT\x00V1\x00"

_MAX_CREDENTIAL_BYTES = 1_048_576
_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
_STORE_ID_PATTERN = re.compile(r"STR-[0-9A-F]{32}")
_GRANT_ID_PATTERN = re.compile(r"SGR-[0-9A-F]{32}")
_SCOPE_GRANT_REVOCATION_ID_PATTERN = re.compile(r"SRV-[0-9A-F]{32}")
_ASSERTION_ID_PATTERN = re.compile(r"PAS-[0-9A-F]{32}")
_PLAN_ID_PATTERN = re.compile(r"CLP-[0-9A-F]{24}")
_WORK_ITEM_ID_PATTERN = re.compile(r"WIT-[A-Z]{2,16}-[0-9A-F]{16}")
_WORK_TRANSITION_ID_PATTERN = re.compile(r"WLT-[0-9A-F]{32}")
_WORK_RECOVERY_REQUEST_ID_PATTERN = re.compile(r"WRQ-[0-9A-F]{32}")
_OWNERSHIP_ENTRY_ID_PATTERN = re.compile(r"OCE-[0-9A-F]{32}")
_OWNERSHIP_PREFLIGHT_ID_PATTERN = re.compile(r"(?:OTP|ORF|OPF)-[0-9A-F]{32}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_BASE64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]+")
_TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_ED25519_FIELD_PRIME = 2**255 - 19
_ED25519_SUBGROUP_ORDER = (
    2**252 + 27742317777372353535851937790883648493
)
_ED25519_D = (
    -121665 * pow(121666, _ED25519_FIELD_PRIME - 2, _ED25519_FIELD_PRIME)
) % _ED25519_FIELD_PRIME
_ED25519_SQRT_MINUS_ONE = pow(
    2,
    (_ED25519_FIELD_PRIME - 1) // 4,
    _ED25519_FIELD_PRIME,
)
_ED25519_IDENTITY = (0, 1, 1, 0)
_VERIFICATION_MAC_KEY = secrets.token_bytes(32)


class PrincipalOperation(StrEnum):
    """Versioned mutation operation identifiers."""

    MISSION_CREATE = "sunderkey.mission.create.v1"
    COLLABORATION_ACTIVATE = "sunderkey.collaboration.activate.v1"
    COLLABORATION_POLICY_OWNER_AUTHORIZE = (
        "sunderkey.collaboration.policy.owner-authorize.v1"
    )
    COLLABORATION_POLICY_CONTROL_APPROVE = (
        "sunderkey.collaboration.policy.control-approve.v1"
    )
    COLLABORATION_PLAN_REPLACEMENT_OWNER_AUTHORIZE = (
        "sunderkey.collaboration.plan-replacement.owner-authorize.v1"
    )
    COLLABORATION_PLAN_REPLACEMENT_CONTROL_APPROVE = (
        "sunderkey.collaboration.plan-replacement.control-approve.v1"
    )
    COLLABORATION_PLAN_REPLACEMENT_CURRENT_OWNER_AUTHORIZE = (
        "sunderkey.collaboration.plan-replacement.current-owner-authorize.v1"
    )
    COLLABORATION_PLAN_REPLACEMENT_PROPOSED_OWNER_ACCEPT = (
        "sunderkey.collaboration.plan-replacement.proposed-owner-accept.v1"
    )
    COLLABORATION_PLAN_REPLACEMENT_SOURCE_COMMAND_REVIEW = (
        "sunderkey.collaboration.plan-replacement.source-command-review.v1"
    )
    COLLABORATION_PLAN_REPLACEMENT_DESTINATION_COMMAND_REVIEW = (
        "sunderkey.collaboration.plan-replacement.destination-command-review.v1"
    )
    COLLABORATION_PLAN_REPLACEMENT_CURRENT_OWNER_CANCEL = (
        "sunderkey.collaboration.plan-replacement.current-owner-cancel.v1"
    )
    COLLABORATION_PLAN_REPLACEMENT_ASSURANCE_APPROVE = (
        "sunderkey.collaboration.plan-replacement.assurance-approve.v1"
    )
    COLLABORATION_PLAN_REPLACEMENT_SECOND_CONTROL_APPROVE = (
        "sunderkey.collaboration.plan-replacement.second-control-approve.v1"
    )
    COLLABORATION_REPLACEMENT_REVIEWER_OWNER_AUTHORIZE = (
        "sunderkey.collaboration.plan-replacement.reviewer-admission.owner-authorize.v1"
    )
    COLLABORATION_REPLACEMENT_REVIEWER_CONTROL_APPROVE = (
        "sunderkey.collaboration.plan-replacement.reviewer-admission.control-approve.v1"
    )
    EXECUTION_CHANNEL_POLICY_OWNER_AUTHORIZE = (
        "sunderkey.collaboration.execution-channel.policy.owner-authorize.v1"
    )
    EXECUTION_CHANNEL_POLICY_CONTROL_APPROVE = (
        "sunderkey.collaboration.execution-channel.policy.control-approve.v1"
    )
    EXECUTION_TRANSFER_REQUEST_AUTHORIZE = (
        "sunderkey.collaboration.execution-transfer.request-authorize.v1"
    )
    EXECUTION_TRANSFER_ACKNOWLEDGE = (
        "sunderkey.collaboration.execution-transfer.acknowledge.v1"
    )
    EXECUTION_TIMEOUT_RESOLVE = (
        "sunderkey.collaboration.execution-transfer.timeout-resolve.v1"
    )
    EXECUTION_SESSION_ACTIVATE_AUTHORIZE = (
        "sunderkey.collaboration.execution-session.activate-authorize.v1"
    )
    EXECUTION_SESSION_ACTIVATE_ACCEPT = (
        "sunderkey.collaboration.execution-session.activate-accept.v1"
    )
    EXECUTION_SESSION_REVOKE = (
        "sunderkey.collaboration.execution-session.revoke.v1"
    )
    EXECUTOR_ACKNOWLEDGE = (
        "sunderkey.collaboration.executor.acknowledge.v1"
    )
    EXECUTOR_ACKNOWLEDGE_SAFETY = (
        "sunderkey.collaboration.executor.acknowledge-safety.v1"
    )
    EVIDENCE_REPOSITORY_ACKNOWLEDGE = (
        "sunderkey.evidence.repository.acknowledge.v1"
    )
    EXECUTOR_DISPATCH_AUTHORIZE = (
        "sunderkey.collaboration.executor.dispatch-authorize.v1"
    )
    EXECUTOR_DISPATCH_SAFETY_AUTHORIZE = (
        "sunderkey.collaboration.executor.dispatch-safety-authorize.v1"
    )
    COLLABORATION_OWNERSHIP_CURRENT_OWNER_AUTHORIZE = (
        "sunderkey.collaboration.ownership.current-owner-authorize.v1"
    )
    COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT = (
        "sunderkey.collaboration.ownership.proposed-owner-accept.v1"
    )
    COLLABORATION_OWNERSHIP_CONTROL_APPROVE = (
        "sunderkey.collaboration.ownership.control-approve.v1"
    )
    COLLABORATION_OWNERSHIP_SECOND_AUTHORITY_APPROVE = (
        "sunderkey.collaboration.ownership.second-authority-approve.v1"
    )
    WORK_CLAIM = "sunderkey.work.claim.v1"
    WORK_RENEW = "sunderkey.work.renew.v1"
    WORK_RELEASE = "sunderkey.work.release.v1"
    WORK_COMPLETE = "sunderkey.work.complete.v1"
    WORK_RECOVERY_REQUEST = "sunderkey.work.recovery.request.v1"
    WORK_RECOVERY_APPROVE = "sunderkey.work.recovery.approve.v1"
    WORK_RECOVERY_DENY = "sunderkey.work.recovery.deny.v1"
    WORK_CANCEL = "sunderkey.work.cancel.v1"
    WORK_HANDOFF_AUTHORIZE = "sunderkey.work.handoff.authorize.v1"
    WORK_HANDOFF_ACCEPT = "sunderkey.work.handoff.accept.v1"
    EVENT_APPEND = "sunderkey.event.append.v1"
    APPROVAL_SUBMIT = "sunderkey.approval.submit.v1"
    APPROVAL_APPROVE = "sunderkey.approval.approve.v1"
    APPROVAL_DENY = "sunderkey.approval.deny.v1"
    APPROVAL_REVOKE = "sunderkey.approval.revoke.v1"
    MISSION_STOP = "sunderkey.mission.stop.v1"
    SIMULATION_RUN = "sunderkey.simulation.run.v1"
    MODEL_EXECUTE = "sunderkey.model.execute.v1"
    EXPERT_REVIEW_SNAPSHOT_REGISTER = (
        "sunderkey.expert.review.snapshot.register.v1"
    )
    EXPERT_WORK_PRODUCT_REVIEW = (
        "sunderkey.expert.work-product.review.v1"
    )
    EXPERT_WORKSPACE_REVIEW_CLOSE = (
        "sunderkey.expert.workspace.review.close.v1"
    )
    EXPERT_WORKSPACE_REVIEW_REVOKE = (
        "sunderkey.expert.workspace.review.revoke.v1"
    )
    ACTION_RESOLVE = "sunderkey.action.resolve.v1"
    ACTION_QUORUM_AUTHORIZE = "sunderkey.action.quorum-authorize.v1"
    ACTION_ADMIT = "sunderkey.action.admit.v1"
    ACTION_ADMISSION_REVOKE = "sunderkey.action.admission-revoke.v1"
    ACTION_AUTHORITY_PUBLISH = "sunderkey.action.authority-publish.v1"
    ACTION_EXECUTE = "sunderkey.action.execute.v1"
    ACTION_EXECUTION_RECONCILE = "sunderkey.action.execution-reconcile.v1"
    TARGET_HEALTH_GATE_RESUME = "sunderkey.target-health-gate.resume.v1"


class TrustKeyState(StrEnum):
    """Lifecycle state for a policy signing key."""

    ACTIVE = "active"
    RETIRING = "retiring"
    REVOKED = "revoked"


class TrustKeyUse(StrEnum):
    """The one credential type a trust key may verify."""

    SCOPE_GRANT = "scope_grant"
    SCOPE_GRANT_REVOCATION = "scope_grant_revocation"
    PRINCIPAL_ASSERTION = "principal_assertion"


EXPIRED_SCOPE_STOP_GRACE_SECONDS = 300
SAFETY_REDUCING_OPERATIONS = frozenset(
    {
        PrincipalOperation.MISSION_STOP,
        PrincipalOperation.EXECUTION_SESSION_REVOKE,
        PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE,
        PrincipalOperation.EXPERT_WORKSPACE_REVIEW_REVOKE,
        PrincipalOperation.ACTION_ADMISSION_REVOKE,
    }
)


def _fail(message: str) -> PrincipalAuthenticationError:
    return PrincipalAuthenticationError(message)


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _fail(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_float(value: str) -> Any:
    raise _fail(f"Floating-point JSON numbers are not permitted: {value}")


def _reject_constant(value: str) -> Any:
    raise _fail(f"Non-finite JSON numbers are not permitted: {value}")


def _parse_json_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > 19:
        raise _fail("JSON integer is outside the signed 64-bit range")
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise _fail("JSON integer is invalid") from exc
    if not -(2**63) <= parsed <= 2**63 - 1:
        raise _fail("JSON integer is outside the signed 64-bit range")
    return parsed


def _load_json_file(path: str | Path, label: str) -> dict[str, Any]:
    file_path = Path(path)
    try:
        before = file_path.stat()
        if not stat.S_ISREG(before.st_mode):
            raise _fail(f"{label} must be a regular file")
        if before.st_size > _MAX_CREDENTIAL_BYTES:
            raise _fail(f"{label} exceeds the maximum size of {_MAX_CREDENTIAL_BYTES} bytes")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(file_path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise _fail(f"{label} must be a regular file")
            if opened.st_size > _MAX_CREDENTIAL_BYTES:
                raise _fail(f"{label} exceeds the maximum size of {_MAX_CREDENTIAL_BYTES} bytes")
            opened_state = (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            )
            if opened_state != (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ):
                raise _fail(f"{label} changed while opening")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                data = stream.read(_MAX_CREDENTIAL_BYTES + 1)
            after_open = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = file_path.stat()
    except OSError as exc:
        raise _fail(f"Could not read {label}: {file_path}") from exc
    if len(data) > _MAX_CREDENTIAL_BYTES:
        raise _fail(f"{label} exceeds the maximum size of {_MAX_CREDENTIAL_BYTES} bytes")
    if (
        len(data) != opened.st_size
        or (
            after_open.st_dev,
            after_open.st_ino,
            after_open.st_size,
            after_open.st_mtime_ns,
        ) != opened_state
        or not stat.S_ISREG(after_path.st_mode)
        or (
            after_path.st_dev,
            after_path.st_ino,
            after_path.st_size,
            after_path.st_mtime_ns,
        ) != opened_state
    ):
        raise _fail(f"{label} changed while reading")
    if data.startswith(b"\xef\xbb\xbf"):
        raise _fail(f"{label} must not contain a UTF-8 BOM")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _fail(f"{label} must be valid UTF-8") from exc
    try:
        raw = json.loads(
            text,
            object_pairs_hook=_strict_pairs,
            parse_float=_reject_float,
            parse_int=_parse_json_int,
            parse_constant=_reject_constant,
        )
    except PrincipalAuthenticationError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise _fail(f"{label} is not valid strict JSON") from exc
    if not isinstance(raw, dict):
        raise _fail(f"{label} must contain one JSON object")
    return raw


def _object(value: Any, label: str, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _fail(f"{label} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise _fail(f"{label} object keys must be strings")
    unknown = sorted(set(value) - fields)
    missing = sorted(fields - set(value))
    if unknown:
        raise _fail(f"{label} contains unknown fields: {', '.join(unknown)}")
    if missing:
        raise _fail(f"{label} is missing required fields: {', '.join(missing)}")
    return value


def _ascii_text(
    value: Any,
    label: str,
    *,
    minimum: int = 1,
    maximum: int = 256,
) -> str:
    if not isinstance(value, str):
        raise _fail(f"{label} must be a string")
    if not minimum <= len(value) <= maximum:
        raise _fail(f"{label} length must be between {minimum} and {maximum}")
    outside_visible_ascii = any(
        ord(character) < 0x21 or ord(character) > 0x7E
        for character in value
    )
    if not value.isascii() or outside_visible_ascii:
        raise _fail(f"{label} must contain visible ASCII characters only")
    return value


def _identifier(value: Any, label: str) -> str:
    result = _ascii_text(value, label, maximum=128)
    if _ID_PATTERN.fullmatch(result) is None:
        raise _fail(f"{label} is not a valid identifier")
    return result


def _store_id(value: Any, label: str = "store_id") -> str:
    result = _ascii_text(value, label, maximum=128)
    if _STORE_ID_PATTERN.fullmatch(result) is None:
        raise _fail(f"{label} must use STR- followed by 32 uppercase hexadecimal characters")
    return result


def _grant_id(value: Any, label: str = "grant_id") -> str:
    result = _ascii_text(value, label, maximum=128)
    if _GRANT_ID_PATTERN.fullmatch(result) is None:
        raise _fail(f"{label} must use SGR- followed by 32 uppercase hexadecimal characters")
    return result


def _scope_grant_revocation_id(
    value: Any,
    label: str = "revocation_id",
) -> str:
    result = _ascii_text(value, label, maximum=128)
    if _SCOPE_GRANT_REVOCATION_ID_PATTERN.fullmatch(result) is None:
        raise _fail(
            f"{label} must use SRV- followed by 32 uppercase hexadecimal characters"
        )
    return result


def _assertion_id(value: Any, label: str = "assertion_id") -> str:
    result = _ascii_text(value, label, maximum=128)
    if _ASSERTION_ID_PATTERN.fullmatch(result) is None:
        raise _fail(f"{label} must use PAS- followed by 32 uppercase hexadecimal characters")
    return result


def _profile_id(value: Any, label: str = "profile_id") -> str:
    result = _ascii_text(value, label, maximum=64)
    if PROFILE_ID_PATTERN.fullmatch(result) is None:
        raise _fail(f"{label} is not a valid SUNDERKEY profile ID")
    return result


def _mission_id(value: Any, label: str = "mission_id") -> str:
    result = _ascii_text(value, label, maximum=64)
    if MISSION_ID_PATTERN.fullmatch(result) is None:
        raise _fail(f"{label} is not a valid mission ID")
    return result


def _plan_id(value: Any, label: str = "plan_id") -> str:
    result = _ascii_text(value, label, maximum=64)
    if _PLAN_ID_PATTERN.fullmatch(result) is None:
        raise _fail(
            f"{label} must use CLP- followed by 24 uppercase "
            "hexadecimal characters"
        )
    return result


def _work_item_id(value: Any, label: str = "work_item_id") -> str:
    result = _ascii_text(value, label, maximum=64)
    if _WORK_ITEM_ID_PATTERN.fullmatch(result) is None:
        raise _fail(f"{label} is not a valid collaboration work item ID")
    return result


def _work_transition_id(
    value: Any,
    label: str = "previous_transition_id",
) -> str:
    result = _ascii_text(value, label, maximum=64)
    if _WORK_TRANSITION_ID_PATTERN.fullmatch(result) is None:
        raise _fail(
            f"{label} must use WLT- followed by 32 uppercase "
            "hexadecimal characters"
        )
    return result


def _work_recovery_request_id(
    value: Any,
    label: str = "recovery_request_id",
) -> str:
    result = _ascii_text(value, label, maximum=64)
    if _WORK_RECOVERY_REQUEST_ID_PATTERN.fullmatch(result) is None:
        raise _fail(
            f"{label} must use WRQ- followed by 32 uppercase "
            "hexadecimal characters"
        )
    return result


def _ownership_entry_id(
    value: Any,
    label: str = "entry_id",
) -> str:
    result = _ascii_text(value, label, maximum=64)
    if _OWNERSHIP_ENTRY_ID_PATTERN.fullmatch(result) is None:
        raise _fail(
            f"{label} must use OCE- followed by 32 uppercase hexadecimal characters"
        )
    return result


def _ownership_preflight_id(
    value: Any,
    label: str = "preflight_id",
) -> str:
    result = _ascii_text(value, label, maximum=64)
    if _OWNERSHIP_PREFLIGHT_ID_PATTERN.fullmatch(result) is None:
        raise _fail(
            f"{label} must use OTP- or ORF- followed by 32 uppercase "
            "hexadecimal characters"
        )
    return result


def _work_item_ids(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise _fail(f"{label} must be an array")
    if not 1 <= len(value) <= 1024:
        raise _fail(f"{label} must contain between 1 and 1024 values")
    result = [
        _work_item_id(item, f"{label}[{index}]")
        for index, item in enumerate(value)
    ]
    if result != sorted(result):
        raise _fail(f"{label} must use canonical sorted order")
    if len(result) != len(set(result)):
        raise _fail(f"{label} must not contain duplicate values")
    return result


def _positive_int(value: Any, label: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(f"{label} must be an integer")
    if not 1 <= value <= maximum:
        raise _fail(f"{label} must be between 1 and {maximum}")
    return value


def _non_negative_int(
    value: Any,
    label: str,
    *,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(f"{label} must be an integer")
    if not 0 <= value <= maximum:
        raise _fail(f"{label} must be between 0 and {maximum}")
    return value


def _policy_version(value: Any, label: str = "policy_version") -> int:
    return _positive_int(value, label, maximum=2_147_483_647)


def _timestamp(value: Any, label: str) -> str:
    result = _ascii_text(value, label, maximum=64)
    if _TIMESTAMP_PATTERN.fullmatch(result) is None:
        raise _fail(f"{label} must use canonical UTC form YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise _fail(f"{label} is not a valid timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != result:
        raise _fail(f"{label} is not a canonical timestamp")
    return result


def _parse_timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    try:
        now = clock()
    except Exception as exc:
        raise _fail("Identity clock failed") from exc
    if not isinstance(now, datetime):
        raise _fail("Identity clock must return a datetime")
    if now.tzinfo is None or now.utcoffset() is None:
        raise _fail("Identity clock must return a timezone-aware datetime")
    return now.astimezone(UTC).replace(microsecond=0)


def _operation(value: Any, label: str) -> PrincipalOperation:
    if not isinstance(value, str):
        raise _fail(f"{label} must be a string")
    try:
        return PrincipalOperation(value)
    except ValueError as exc:
        raise _fail(f"{label} is not a supported versioned operation") from exc


def _environment(value: Any, label: str) -> MissionEnvironment:
    if not isinstance(value, str):
        raise _fail(f"{label} must be a string")
    try:
        return MissionEnvironment(value)
    except ValueError as exc:
        raise _fail(f"{label} is not a supported mission environment") from exc


def _action_tier(value: Any, label: str) -> ActionTier:
    if not isinstance(value, str):
        raise _fail(f"{label} must be a string")
    try:
        return ActionTier(value)
    except ValueError as exc:
        raise _fail(f"{label} is not a supported action tier") from exc


def _sorted_unique_texts(
    value: Any,
    label: str,
    parser: Callable[[Any, str], str],
    *,
    maximum_items: int = 4096,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise _fail(f"{label} must be an array")
    if not 1 <= len(value) <= maximum_items:
        raise _fail(f"{label} must contain between 1 and {maximum_items} values")
    result = tuple(parser(item, f"{label}[{index}]") for index, item in enumerate(value))
    if len(result) != len(set(result)):
        raise _fail(f"{label} must not contain duplicate values")
    if result != tuple(sorted(result)):
        raise _fail(f"{label} must use ascending canonical order")
    return result


def _sorted_unique_operations(value: Any, label: str) -> tuple[PrincipalOperation, ...]:
    if not isinstance(value, list):
        raise _fail(f"{label} must be an array")
    if not 1 <= len(value) <= len(PrincipalOperation):
        raise _fail(f"{label} must contain between 1 and {len(PrincipalOperation)} values")
    result = tuple(_operation(item, f"{label}[{index}]") for index, item in enumerate(value))
    raw = tuple(operation.value for operation in result)
    if len(raw) != len(set(raw)):
        raise _fail(f"{label} must not contain duplicate values")
    if raw != tuple(sorted(raw)):
        raise _fail(f"{label} must use ascending canonical order")
    return result


def _base64url(value: Any, label: str, *, decoded_length: int) -> str:
    result = _ascii_text(value, label, maximum=max(128, decoded_length * 2))
    if "=" in result or _BASE64URL_PATTERN.fullmatch(result) is None:
        raise _fail(f"{label} must be unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(result + "=" * (-len(result) % 4))
    except (ValueError, binascii.Error) as exc:
        raise _fail(f"{label} is not valid base64url") from exc
    if len(decoded) != decoded_length:
        raise _fail(f"{label} must decode to exactly {decoded_length} bytes")
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != result:
        raise _fail(f"{label} is not canonical base64url")
    return result


def _decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _ed25519_point_add(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    prime = _ED25519_FIELD_PRIME
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = ((y1 - x1) * (y2 - x2)) % prime
    b = ((y1 + x1) * (y2 + x2)) % prime
    c = (2 * _ED25519_D * t1 * t2) % prime
    d = (2 * z1 * z2) % prime
    e = (b - a) % prime
    f = (d - c) % prime
    g = (d + c) % prime
    h = (b + a) % prime
    return (
        (e * f) % prime,
        (g * h) % prime,
        (f * g) % prime,
        (e * h) % prime,
    )


def _ed25519_point_multiply(
    scalar: int,
    point: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    result = _ED25519_IDENTITY
    addend = point
    remaining = scalar
    while remaining:
        if remaining & 1:
            result = _ed25519_point_add(result, addend)
        addend = _ed25519_point_add(addend, addend)
        remaining >>= 1
    return result


def _ed25519_points_equal(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> bool:
    prime = _ED25519_FIELD_PRIME
    return (
        (left[0] * right[2] - right[0] * left[2]) % prime == 0
        and (left[1] * right[2] - right[1] * left[2]) % prime == 0
    )


def _ed25519_decode_point(
    encoded: bytes,
) -> tuple[int, int, int, int] | None:
    if len(encoded) != 32:
        return None
    compressed = int.from_bytes(encoded, "little")
    sign = compressed >> 255
    y = compressed & ((1 << 255) - 1)
    prime = _ED25519_FIELD_PRIME
    if y >= prime:
        return None
    y_squared = y * y % prime
    denominator = (_ED25519_D * y_squared + 1) % prime
    if denominator == 0:
        return None
    x_squared = (
        (y_squared - 1)
        * pow(denominator, prime - 2, prime)
    ) % prime
    x = pow(x_squared, (prime + 3) // 8, prime)
    if x * x % prime != x_squared:
        x = x * _ED25519_SQRT_MINUS_ONE % prime
    if x * x % prime != x_squared:
        return None
    if x == 0 and sign == 1:
        return None
    if x & 1 != sign:
        x = prime - x
    point = (x, y, 1, x * y % prime)
    recompressed = y | ((x & 1) << 255)
    if recompressed.to_bytes(32, "little") != encoded:
        return None
    return point


@lru_cache(maxsize=2048)
def _ed25519_is_prime_order_point(encoded: bytes) -> bool:
    point = _ed25519_decode_point(encoded)
    if point is None or _ed25519_points_equal(point, _ED25519_IDENTITY):
        return False
    multiplied = _ed25519_point_multiply(
        _ED25519_SUBGROUP_ORDER,
        point,
    )
    return _ed25519_points_equal(multiplied, _ED25519_IDENTITY)


def _strict_ed25519_public_key(
    value: bytes | Ed25519PublicKey,
    label: str,
) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        raw = value.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    elif isinstance(value, bytes):
        raw = value
    else:
        raise _fail(f"{label} must be 32 raw Ed25519 public bytes")
    if len(raw) != 32 or not _ed25519_is_prime_order_point(raw):
        raise _fail(
            f"{label} must be a canonical prime-order Ed25519 public key"
        )
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise _fail(f"{label} is not a valid Ed25519 public key") from exc


def _sha256(value: Any, label: str) -> str:
    result = _ascii_text(value, label, maximum=71)
    if _SHA256_PATTERN.fullmatch(result) is None:
        raise _fail(f"{label} must use sha256 followed by 64 lowercase hexadecimal characters")
    return result


def _event_id(value: Any, label: str) -> str:
    result = _ascii_text(value, label, maximum=96)
    if EVENT_ID_PATTERN.fullmatch(result) is None:
        raise _fail(f"{label} is not a valid event ID")
    return result


def _approval_id(value: Any, label: str) -> str:
    result = _ascii_text(value, label, maximum=64)
    if APPROVAL_ID_PATTERN.fullmatch(result) is None:
        raise _fail(f"{label} is not a valid approval ID")
    return result


def _non_negative_int_or_none(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(f"{label} must be a non-negative integer or null")
    if not 0 <= value <= 2_147_483_647:
        raise _fail(f"{label} must be between 0 and 2147483647")
    return value


def _intent_constraints(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise _fail(f"{label} must be an array")
    if not 1 <= len(value) <= 64:
        raise _fail(f"{label} must contain between 1 and 64 values")
    result = [
        _intent_text(item, f"{label}[{index}]", maximum=512)
        for index, item in enumerate(value)
    ]
    if len(result) != len(set(result)):
        raise _fail(f"{label} must not contain duplicate values")
    return result


def _intent_text(value: Any, label: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise _fail(f"{label} must be a string")
    if not 1 <= len(value) <= maximum:
        raise _fail(f"{label} length must be between 1 and {maximum}")
    if (
        not value.isascii()
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
        or not any(ord(character) > 0x20 for character in value)
    ):
        raise _fail(f"{label} must contain printable ASCII text")
    return value


def _canonical_json(value: Any, label: str = "value") -> str:
    def validate(item: Any, path: str) -> None:
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, str):
            if (
                len(item) > 65_536
                or not item.isascii()
                or any(
                    ord(character) < 0x20
                    or ord(character) > 0x7E
                    for character in item
                )
            ):
                raise _fail(
                    f"{path} must contain canonical printable ASCII text"
                )
            return
        if isinstance(item, int):
            if not -(2**63) <= item <= 2**63 - 1:
                raise _fail(f"{path} integer is outside the signed 64-bit range")
            return
        if isinstance(item, float):
            raise _fail(f"{path} must not contain floating-point values")
        if isinstance(item, list | tuple):
            for index, member in enumerate(item):
                validate(member, f"{path}[{index}]")
            return
        if isinstance(item, dict):
            for key, member in item.items():
                _ascii_text(key, f"{path} object key", maximum=256)
                validate(member, f"{path}.{key}")
            return
        raise _fail(f"{path} contains an unsupported JSON value")

    validate(value, label)
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise _fail(f"{label} could not be serialized canonically") from exc


def _hash_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _content_hash(value: Mapping[str, Any]) -> str:
    return _hash_bytes(_canonical_json(dict(value)).encode("ascii"))


def _verification_proof(kind: str, material: Mapping[str, Any]) -> bytes:
    payload = _canonical_json(
        {
            "kind": kind,
            "material": dict(material),
        },
        label="verification proof",
    ).encode("ascii")
    return hmac.new(
        _VERIFICATION_MAC_KEY,
        payload,
        hashlib.sha256,
    ).digest()


def _verify_window(
    *,
    issued_at: str,
    not_before: str,
    expires_at: str,
    now: datetime,
    label: str,
    maximum_lifetime_seconds: int | None = None,
    allow_expired: bool = False,
) -> bool:
    issued = _parse_timestamp(issued_at)
    starts = _parse_timestamp(not_before)
    expires = _parse_timestamp(expires_at)
    if issued > starts:
        raise _fail(f"{label} issued_at must not be after not_before")
    if starts >= expires:
        raise _fail(f"{label} not_before must be before expires_at")
    if maximum_lifetime_seconds is not None:
        lifetime = int((expires - issued).total_seconds())
        if lifetime > maximum_lifetime_seconds:
            raise _fail(f"{label} exceeds the configured maximum lifetime")
    if now < starts:
        raise _fail(f"{label} is not active yet")
    if now >= expires:
        if allow_expired:
            return False
        raise _fail(f"{label} has expired")
    return True


def _verify_ed25519(
    public_key: bytes | Ed25519PublicKey,
    signature: str,
    message: bytes,
    label: str,
) -> None:
    signature_bytes = _decode_base64url(signature)
    if (
        len(signature_bytes) != 64
        or not _ed25519_is_prime_order_point(signature_bytes[:32])
        or int.from_bytes(signature_bytes[32:], "little")
        >= _ED25519_SUBGROUP_ORDER
    ):
        raise _fail(f"{label} signature is not strict canonical Ed25519")
    verifier = _strict_ed25519_public_key(
        public_key,
        f"{label} verification key",
    )
    try:
        verifier.verify(signature_bytes, message)
    except InvalidSignature as exc:
        raise _fail(f"{label} signature verification failed") from exc


@dataclass(frozen=True)
class TrustKey:
    """A public signing key constrained by exact principal allowlists."""

    key_id: str
    issuer: str
    public_key: str
    key_use: TrustKeyUse
    state: TrustKeyState
    not_before: str
    not_after: str
    retire_at: str | None
    allowed_profiles: tuple[str, ...]
    allowed_subjects: tuple[str, ...]
    allowed_operations: tuple[PrincipalOperation, ...]

    @classmethod
    def from_dict(cls, raw: Any, *, label: str = "trust key") -> TrustKey:
        fields = {
            "key_id",
            "issuer",
            "public_key",
            "key_use",
            "state",
            "not_before",
            "not_after",
            "retire_at",
            "allowed_profiles",
            "allowed_subjects",
            "allowed_operations",
        }
        value = _object(raw, label, fields)
        try:
            state = TrustKeyState(value["state"])
        except (TypeError, ValueError) as exc:
            raise _fail(f"{label}.state must be active, retiring, or revoked") from exc
        try:
            key_use = TrustKeyUse(value["key_use"])
        except (TypeError, ValueError) as exc:
            raise _fail(
                f"{label}.key_use must be principal_assertion, scope_grant, "
                "or scope_grant_revocation"
            ) from exc
        retire_raw = value["retire_at"]
        retire_at = None if retire_raw is None else _timestamp(retire_raw, f"{label}.retire_at")
        if state is TrustKeyState.RETIRING and retire_at is None:
            raise _fail(f"{label}.retire_at is required for a retiring key")
        if state is TrustKeyState.ACTIVE and retire_at is not None:
            raise _fail(f"{label}.retire_at must be null for an active key")
        public_key = _base64url(
            value["public_key"],
            f"{label}.public_key",
            decoded_length=32,
        )
        _strict_ed25519_public_key(
            _decode_base64url(public_key),
            f"{label}.public_key",
        )
        key = cls(
            key_id=_identifier(value["key_id"], f"{label}.key_id"),
            issuer=_identifier(value["issuer"], f"{label}.issuer"),
            public_key=public_key,
            key_use=key_use,
            state=state,
            not_before=_timestamp(value["not_before"], f"{label}.not_before"),
            not_after=_timestamp(value["not_after"], f"{label}.not_after"),
            retire_at=retire_at,
            allowed_profiles=_sorted_unique_texts(
                value["allowed_profiles"],
                f"{label}.allowed_profiles",
                _profile_id,
            ),
            allowed_subjects=_sorted_unique_texts(
                value["allowed_subjects"],
                f"{label}.allowed_subjects",
                _ascii_text,
            ),
            allowed_operations=_sorted_unique_operations(
                value["allowed_operations"],
                f"{label}.allowed_operations",
            ),
        )
        if _parse_timestamp(key.not_before) >= _parse_timestamp(key.not_after):
            raise _fail(f"{label}.not_before must be before not_after")
        if key.retire_at is not None:
            retirement = _parse_timestamp(key.retire_at)
            if not _parse_timestamp(key.not_before) <= retirement < _parse_timestamp(key.not_after):
                raise _fail(f"{label}.retire_at must fall inside the key validity window")
        return key

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "issuer": self.issuer,
            "public_key": self.public_key,
            "key_use": self.key_use.value,
            "state": self.state.value,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "retire_at": self.retire_at,
            "allowed_profiles": list(self.allowed_profiles),
            "allowed_subjects": list(self.allowed_subjects),
            "allowed_operations": [operation.value for operation in self.allowed_operations],
        }

    @property
    def content_sha256(self) -> str:
        return _content_hash(self.to_dict())

    def ed25519_public_key(self) -> Ed25519PublicKey:
        return _strict_ed25519_public_key(
            _decode_base64url(self.public_key),
            f"Trust key {self.key_id} public key",
        )


@dataclass(frozen=True)
class PrincipalTrustPolicy:
    """Root-signed policy that defines trusted runtime principal keys."""

    schema_version: int
    policy_id: str
    policy_version: int
    issuer: str
    audience: str
    store_id: str
    issued_at: str
    not_before: str
    expires_at: str
    max_scope_lifetime_seconds: int
    max_assertion_lifetime_seconds: int
    allowed_profiles: tuple[str, ...]
    allowed_subjects: tuple[str, ...]
    allowed_operations: tuple[PrincipalOperation, ...]
    keys: tuple[TrustKey, ...]
    root_key_id: str
    signature: str

    @classmethod
    def from_dict(cls, raw: Any) -> PrincipalTrustPolicy:
        fields = {
            "schema_version",
            "policy_id",
            "policy_version",
            "issuer",
            "audience",
            "store_id",
            "issued_at",
            "not_before",
            "expires_at",
            "max_scope_lifetime_seconds",
            "max_assertion_lifetime_seconds",
            "allowed_profiles",
            "allowed_subjects",
            "allowed_operations",
            "keys",
            "root_key_id",
            "signature",
        }
        value = _object(raw, "principal trust policy", fields)
        if value["schema_version"] != 1 or isinstance(value["schema_version"], bool):
            raise _fail("principal trust policy schema_version must be 1")
        keys_raw = value["keys"]
        if not isinstance(keys_raw, list) or not 1 <= len(keys_raw) <= 128:
            raise _fail("principal trust policy keys must contain between 1 and 128 values")
        keys = tuple(
            TrustKey.from_dict(item, label=f"principal trust policy keys[{index}]")
            for index, item in enumerate(keys_raw)
        )
        if tuple(key.key_id for key in keys) != tuple(sorted(key.key_id for key in keys)):
            raise _fail("principal trust policy keys must use ascending key_id order")
        if len({key.key_id for key in keys}) != len(keys):
            raise _fail("principal trust policy keys must not contain duplicate key IDs")
        if len({key.public_key for key in keys}) != len(keys):
            raise _fail(
                "principal trust policy keys must use distinct Ed25519 public key material"
            )
        policy = cls(
            schema_version=1,
            policy_id=_identifier(value["policy_id"], "principal trust policy policy_id"),
            policy_version=_policy_version(
                value["policy_version"],
                "principal trust policy policy_version",
            ),
            issuer=_identifier(value["issuer"], "principal trust policy issuer"),
            audience=_identifier(value["audience"], "principal trust policy audience"),
            store_id=_store_id(value["store_id"], "principal trust policy store_id"),
            issued_at=_timestamp(value["issued_at"], "principal trust policy issued_at"),
            not_before=_timestamp(value["not_before"], "principal trust policy not_before"),
            expires_at=_timestamp(value["expires_at"], "principal trust policy expires_at"),
            max_scope_lifetime_seconds=_positive_int(
                value["max_scope_lifetime_seconds"],
                "principal trust policy max_scope_lifetime_seconds",
                maximum=31_536_000,
            ),
            max_assertion_lifetime_seconds=_positive_int(
                value["max_assertion_lifetime_seconds"],
                "principal trust policy max_assertion_lifetime_seconds",
                maximum=86_400,
            ),
            allowed_profiles=_sorted_unique_texts(
                value["allowed_profiles"],
                "principal trust policy allowed_profiles",
                _profile_id,
            ),
            allowed_subjects=_sorted_unique_texts(
                value["allowed_subjects"],
                "principal trust policy allowed_subjects",
                _ascii_text,
            ),
            allowed_operations=_sorted_unique_operations(
                value["allowed_operations"],
                "principal trust policy allowed_operations",
            ),
            keys=keys,
            root_key_id=_identifier(
                value["root_key_id"],
                "principal trust policy root_key_id",
            ),
            signature=_base64url(
                value["signature"],
                "principal trust policy signature",
                decoded_length=64,
            ),
        )
        _verify_window(
            issued_at=policy.issued_at,
            not_before=policy.not_before,
            expires_at=policy.expires_at,
            now=_parse_timestamp(policy.not_before),
            label="principal trust policy",
        )
        profile_set = set(policy.allowed_profiles)
        subject_set = set(policy.allowed_subjects)
        operation_set = set(policy.allowed_operations)
        if policy.root_key_id in {key.key_id for key in policy.keys}:
            raise _fail(
                "principal trust policy root_key_id must not be reused by an issuer key"
            )
        for key in policy.keys:
            if not set(key.allowed_profiles) <= profile_set:
                raise _fail(f"Trust key {key.key_id} allows profiles outside the policy")
            if not set(key.allowed_subjects) <= subject_set:
                raise _fail(f"Trust key {key.key_id} allows subjects outside the policy")
            if not set(key.allowed_operations) <= operation_set:
                raise _fail(f"Trust key {key.key_id} allows operations outside the policy")
        return policy

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "issuer": self.issuer,
            "audience": self.audience,
            "store_id": self.store_id,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "max_scope_lifetime_seconds": self.max_scope_lifetime_seconds,
            "max_assertion_lifetime_seconds": self.max_assertion_lifetime_seconds,
            "allowed_profiles": list(self.allowed_profiles),
            "allowed_subjects": list(self.allowed_subjects),
            "allowed_operations": [operation.value for operation in self.allowed_operations],
            "keys": [key.to_dict() for key in self.keys],
            "root_key_id": self.root_key_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return TRUST_POLICY_SIGNING_DOMAIN + _canonical_json(self.unsigned_dict()).encode("ascii")

    @property
    def content_sha256(self) -> str:
        return _content_hash(self.to_dict())

    def key(self, key_id: str) -> TrustKey:
        for key in self.keys:
            if key.key_id == key_id:
                return key
        raise _fail(f"Trust policy does not contain key: {key_id}")


@dataclass(frozen=True)
class ScopeGrant:
    """A signed mission scope grant for one principal and profile."""

    schema_version: int
    grant_id: str
    policy_id: str
    policy_version: int
    issuer: str
    key_id: str
    subject: str
    profile_id: str
    audience: str
    store_id: str
    mission_id: str
    mission_context_hash: str
    scope_reference: str
    scope_document_hash: str
    environment: MissionEnvironment
    max_action_tier: ActionTier
    constraints_hash: str
    operations: tuple[PrincipalOperation, ...]
    issued_at: str
    not_before: str
    expires_at: str
    signature: str

    @classmethod
    def from_dict(cls, raw: Any) -> ScopeGrant:
        fields = {
            "schema_version",
            "grant_id",
            "policy_id",
            "policy_version",
            "issuer",
            "key_id",
            "subject",
            "profile_id",
            "audience",
            "store_id",
            "mission_id",
            "mission_context_hash",
            "scope_reference",
            "scope_document_hash",
            "environment",
            "max_action_tier",
            "constraints_hash",
            "operations",
            "issued_at",
            "not_before",
            "expires_at",
            "signature",
        }
        value = _object(raw, "scope grant", fields)
        if value["schema_version"] != 1 or isinstance(value["schema_version"], bool):
            raise _fail("scope grant schema_version must be 1")
        grant = cls(
            schema_version=1,
            grant_id=_grant_id(value["grant_id"], "scope grant grant_id"),
            policy_id=_identifier(value["policy_id"], "scope grant policy_id"),
            policy_version=_policy_version(
                value["policy_version"],
                "scope grant policy_version",
            ),
            issuer=_identifier(value["issuer"], "scope grant issuer"),
            key_id=_identifier(value["key_id"], "scope grant key_id"),
            subject=_ascii_text(value["subject"], "scope grant subject"),
            profile_id=_profile_id(value["profile_id"], "scope grant profile_id"),
            audience=_identifier(value["audience"], "scope grant audience"),
            store_id=_store_id(value["store_id"], "scope grant store_id"),
            mission_id=_mission_id(value["mission_id"], "scope grant mission_id"),
            mission_context_hash=_sha256(
                value["mission_context_hash"],
                "scope grant mission_context_hash",
            ),
            scope_reference=_ascii_text(
                value["scope_reference"],
                "scope grant scope_reference",
                maximum=512,
            ),
            scope_document_hash=_sha256(
                value["scope_document_hash"],
                "scope grant scope_document_hash",
            ),
            environment=_environment(value["environment"], "scope grant environment"),
            max_action_tier=_action_tier(
                value["max_action_tier"],
                "scope grant max_action_tier",
            ),
            constraints_hash=_sha256(
                value["constraints_hash"],
                "scope grant constraints_hash",
            ),
            operations=_sorted_unique_operations(value["operations"], "scope grant operations"),
            issued_at=_timestamp(value["issued_at"], "scope grant issued_at"),
            not_before=_timestamp(value["not_before"], "scope grant not_before"),
            expires_at=_timestamp(value["expires_at"], "scope grant expires_at"),
            signature=_base64url(
                value["signature"],
                "scope grant signature",
                decoded_length=64,
            ),
        )
        _verify_window(
            issued_at=grant.issued_at,
            not_before=grant.not_before,
            expires_at=grant.expires_at,
            now=_parse_timestamp(grant.not_before),
            label="scope grant",
        )
        return grant

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "grant_id": self.grant_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "issuer": self.issuer,
            "key_id": self.key_id,
            "subject": self.subject,
            "profile_id": self.profile_id,
            "audience": self.audience,
            "store_id": self.store_id,
            "mission_id": self.mission_id,
            "mission_context_hash": self.mission_context_hash,
            "scope_reference": self.scope_reference,
            "scope_document_hash": self.scope_document_hash,
            "environment": self.environment.value,
            "max_action_tier": self.max_action_tier.value,
            "constraints_hash": self.constraints_hash,
            "operations": [operation.value for operation in self.operations],
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return SCOPE_GRANT_SIGNING_DOMAIN + _canonical_json(self.unsigned_dict()).encode("ascii")

    @property
    def content_sha256(self) -> str:
        return _content_hash(self.to_dict())


@dataclass(frozen=True)
class ScopeGrantRevocation:
    """A signed authorization to revoke one accepted mission scope grant."""

    schema_version: int
    revocation_id: str
    policy_id: str
    policy_version: int
    issuer: str
    key_id: str
    audience: str
    store_id: str
    mission_id: str
    mission_context_hash: str
    scope_grant_issuer: str
    scope_grant_id: str
    scope_grant_sha256: str
    scope_grant_subject: str
    scope_grant_profile_id: str
    reason_code: str
    reason: str
    issued_at: str
    not_before: str
    expires_at: str
    signature: str

    @classmethod
    def from_dict(cls, raw: Any) -> ScopeGrantRevocation:
        fields = {
            "schema_version",
            "revocation_id",
            "policy_id",
            "policy_version",
            "issuer",
            "key_id",
            "audience",
            "store_id",
            "mission_id",
            "mission_context_hash",
            "scope_grant_issuer",
            "scope_grant_id",
            "scope_grant_sha256",
            "scope_grant_subject",
            "scope_grant_profile_id",
            "reason_code",
            "reason",
            "issued_at",
            "not_before",
            "expires_at",
            "signature",
        }
        value = _object(raw, "scope grant revocation", fields)
        if (
            not isinstance(value["schema_version"], int)
            or isinstance(value["schema_version"], bool)
            or value["schema_version"] != 1
        ):
            raise _fail("scope grant revocation schema_version must be 1")
        revocation = cls(
            schema_version=1,
            revocation_id=_scope_grant_revocation_id(
                value["revocation_id"],
                "scope grant revocation revocation_id",
            ),
            policy_id=_identifier(
                value["policy_id"],
                "scope grant revocation policy_id",
            ),
            policy_version=_policy_version(
                value["policy_version"],
                "scope grant revocation policy_version",
            ),
            issuer=_identifier(
                value["issuer"],
                "scope grant revocation issuer",
            ),
            key_id=_identifier(
                value["key_id"],
                "scope grant revocation key_id",
            ),
            audience=_identifier(
                value["audience"],
                "scope grant revocation audience",
            ),
            store_id=_store_id(
                value["store_id"],
                "scope grant revocation store_id",
            ),
            mission_id=_mission_id(
                value["mission_id"],
                "scope grant revocation mission_id",
            ),
            mission_context_hash=_sha256(
                value["mission_context_hash"],
                "scope grant revocation mission_context_hash",
            ),
            scope_grant_issuer=_identifier(
                value["scope_grant_issuer"],
                "scope grant revocation scope_grant_issuer",
            ),
            scope_grant_id=_grant_id(
                value["scope_grant_id"],
                "scope grant revocation scope_grant_id",
            ),
            scope_grant_sha256=_sha256(
                value["scope_grant_sha256"],
                "scope grant revocation scope_grant_sha256",
            ),
            scope_grant_subject=_ascii_text(
                value["scope_grant_subject"],
                "scope grant revocation scope_grant_subject",
            ),
            scope_grant_profile_id=_profile_id(
                value["scope_grant_profile_id"],
                "scope grant revocation scope_grant_profile_id",
            ),
            reason_code=_identifier(
                value["reason_code"],
                "scope grant revocation reason_code",
            ),
            reason=_intent_text(
                value["reason"],
                "scope grant revocation reason",
            ),
            issued_at=_timestamp(
                value["issued_at"],
                "scope grant revocation issued_at",
            ),
            not_before=_timestamp(
                value["not_before"],
                "scope grant revocation not_before",
            ),
            expires_at=_timestamp(
                value["expires_at"],
                "scope grant revocation expires_at",
            ),
            signature=_base64url(
                value["signature"],
                "scope grant revocation signature",
                decoded_length=64,
            ),
        )
        _verify_window(
            issued_at=revocation.issued_at,
            not_before=revocation.not_before,
            expires_at=revocation.expires_at,
            now=_parse_timestamp(revocation.not_before),
            label="scope grant revocation",
        )
        return revocation

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "revocation_id": self.revocation_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "issuer": self.issuer,
            "key_id": self.key_id,
            "audience": self.audience,
            "store_id": self.store_id,
            "mission_id": self.mission_id,
            "mission_context_hash": self.mission_context_hash,
            "scope_grant_issuer": self.scope_grant_issuer,
            "scope_grant_id": self.scope_grant_id,
            "scope_grant_sha256": self.scope_grant_sha256,
            "scope_grant_subject": self.scope_grant_subject,
            "scope_grant_profile_id": self.scope_grant_profile_id,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return SCOPE_GRANT_REVOCATION_SIGNING_DOMAIN + _canonical_json(
            self.unsigned_dict()
        ).encode("ascii")

    @property
    def content_sha256(self) -> str:
        return _content_hash(self.to_dict())


@dataclass(frozen=True)
class PrincipalAssertion:
    """A signed, operation-specific principal assertion."""

    schema_version: int
    assertion_id: str
    policy_id: str
    policy_version: int
    scope_grant_id: str
    scope_grant_sha256: str
    issuer: str
    key_id: str
    subject: str
    profile_id: str
    audience: str
    store_id: str
    mission_id: str
    operation: PrincipalOperation
    operation_intent_sha256: str
    issued_at: str
    not_before: str
    expires_at: str
    signature: str

    @classmethod
    def from_dict(cls, raw: Any) -> PrincipalAssertion:
        fields = {
            "schema_version",
            "assertion_id",
            "policy_id",
            "policy_version",
            "scope_grant_id",
            "scope_grant_sha256",
            "issuer",
            "key_id",
            "subject",
            "profile_id",
            "audience",
            "store_id",
            "mission_id",
            "operation",
            "operation_intent_sha256",
            "issued_at",
            "not_before",
            "expires_at",
            "signature",
        }
        value = _object(raw, "principal assertion", fields)
        if value["schema_version"] != 1 or isinstance(value["schema_version"], bool):
            raise _fail("principal assertion schema_version must be 1")
        assertion = cls(
            schema_version=1,
            assertion_id=_assertion_id(
                value["assertion_id"],
                "principal assertion assertion_id",
            ),
            policy_id=_identifier(value["policy_id"], "principal assertion policy_id"),
            policy_version=_policy_version(
                value["policy_version"],
                "principal assertion policy_version",
            ),
            scope_grant_id=_grant_id(
                value["scope_grant_id"],
                "principal assertion scope_grant_id",
            ),
            scope_grant_sha256=_sha256(
                value["scope_grant_sha256"],
                "principal assertion scope_grant_sha256",
            ),
            issuer=_identifier(value["issuer"], "principal assertion issuer"),
            key_id=_identifier(value["key_id"], "principal assertion key_id"),
            subject=_ascii_text(value["subject"], "principal assertion subject"),
            profile_id=_profile_id(value["profile_id"], "principal assertion profile_id"),
            audience=_identifier(value["audience"], "principal assertion audience"),
            store_id=_store_id(value["store_id"], "principal assertion store_id"),
            mission_id=_mission_id(value["mission_id"], "principal assertion mission_id"),
            operation=_operation(value["operation"], "principal assertion operation"),
            operation_intent_sha256=_sha256(
                value["operation_intent_sha256"],
                "principal assertion operation_intent_sha256",
            ),
            issued_at=_timestamp(value["issued_at"], "principal assertion issued_at"),
            not_before=_timestamp(value["not_before"], "principal assertion not_before"),
            expires_at=_timestamp(value["expires_at"], "principal assertion expires_at"),
            signature=_base64url(
                value["signature"],
                "principal assertion signature",
                decoded_length=64,
            ),
        )
        _verify_window(
            issued_at=assertion.issued_at,
            not_before=assertion.not_before,
            expires_at=assertion.expires_at,
            now=_parse_timestamp(assertion.not_before),
            label="principal assertion",
        )
        return assertion

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "assertion_id": self.assertion_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "scope_grant_id": self.scope_grant_id,
            "scope_grant_sha256": self.scope_grant_sha256,
            "issuer": self.issuer,
            "key_id": self.key_id,
            "subject": self.subject,
            "profile_id": self.profile_id,
            "audience": self.audience,
            "store_id": self.store_id,
            "mission_id": self.mission_id,
            "operation": self.operation.value,
            "operation_intent_sha256": self.operation_intent_sha256,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return PRINCIPAL_ASSERTION_SIGNING_DOMAIN + _canonical_json(
            self.unsigned_dict()
        ).encode("ascii")

    @property
    def content_sha256(self) -> str:
        return _content_hash(self.to_dict())


@dataclass(frozen=True)
class VerifiedTrustPolicy:
    """A trust policy whose root signature and validity have been checked."""

    policy: PrincipalTrustPolicy
    policy_sha256: str
    verified_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self._proof_is_valid():
            raise TypeError(
                "VerifiedTrustPolicy can be created only by verify_trust_policy"
            )

    def _proof_is_valid(self) -> bool:
        expected = _verification_proof(
            "verified_trust_policy",
            {
                "policy": self.policy.to_dict(),
                "policy_sha256": self.policy_sha256,
                "verified_at": self.verified_at,
            },
        )
        return isinstance(self._proof, bytes) and hmac.compare_digest(
            self._proof,
            expected,
        )

    @property
    def policy_id(self) -> str:
        return self.policy.policy_id

    @property
    def policy_version(self) -> int:
        return self.policy.policy_version

    @property
    def store_id(self) -> str:
        return self.policy.store_id


@dataclass(frozen=True)
class VerifiedScopeGrant:
    """A scope grant whose policy key signature and constraints were checked."""

    grant: ScopeGrant
    grant_sha256: str
    key_sha256: str
    policy_sha256: str
    verified_operation: PrincipalOperation
    scope_active: bool
    safety_reduction_only: bool
    verified_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self._proof_is_valid():
            raise TypeError(
                "VerifiedScopeGrant can be created only by verify_scope_grant"
            )

    def _proof_is_valid(self) -> bool:
        expected = _verification_proof(
            "verified_scope_grant",
            {
                "grant": self.grant.to_dict(),
                "grant_sha256": self.grant_sha256,
                "key_sha256": self.key_sha256,
                "policy_sha256": self.policy_sha256,
                "safety_reduction_only": self.safety_reduction_only,
                "scope_active": self.scope_active,
                "verified_at": self.verified_at,
                "verified_operation": self.verified_operation.value,
            },
        )
        return isinstance(self._proof, bytes) and hmac.compare_digest(
            self._proof,
            expected,
        )


@dataclass(frozen=True)
class VerifiedScopeGrantRevocation:
    """A scope revocation whose policy key and target bindings were checked."""

    revocation: ScopeGrantRevocation
    revocation_sha256: str
    target_grant_sha256: str
    key_sha256: str
    policy_sha256: str
    verified_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self._proof_is_valid():
            raise TypeError(
                "VerifiedScopeGrantRevocation can be created only by "
                "verify_scope_grant_revocation"
            )

    def _proof_is_valid(self) -> bool:
        expected = _verification_proof(
            "verified_scope_grant_revocation",
            {
                "revocation": self.revocation.to_dict(),
                "revocation_sha256": self.revocation_sha256,
                "target_grant_sha256": self.target_grant_sha256,
                "key_sha256": self.key_sha256,
                "policy_sha256": self.policy_sha256,
                "verified_at": self.verified_at,
            },
        )
        return isinstance(self._proof, bytes) and hmac.compare_digest(
            self._proof,
            expected,
        )


@dataclass(frozen=True)
class VerifiedPrincipal:
    """Authenticated principal data derived from verified credentials."""

    assertion_id: str
    assertion_sha256: str
    subject: str
    profile_id: str
    issuer: str
    key_id: str
    key_sha256: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    scope_grant_id: str
    scope_grant_sha256: str
    audience: str
    store_id: str
    mission_id: str
    operation: PrincipalOperation
    operation_intent_sha256: str
    authenticated_at: str
    expires_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self._proof_is_valid():
            raise TypeError(
                "VerifiedPrincipal can be created only by verify_principal_assertion"
            )

    def _proof_is_valid(self) -> bool:
        expected = _verification_proof(
            "verified_principal",
            self.to_dict(),
        )
        return isinstance(self._proof, bytes) and hmac.compare_digest(
            self._proof,
            expected,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "assertion_id": self.assertion_id,
            "assertion_sha256": self.assertion_sha256,
            "subject": self.subject,
            "profile_id": self.profile_id,
            "issuer": self.issuer,
            "key_id": self.key_id,
            "key_sha256": self.key_sha256,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "scope_grant_id": self.scope_grant_id,
            "scope_grant_sha256": self.scope_grant_sha256,
            "audience": self.audience,
            "store_id": self.store_id,
            "mission_id": self.mission_id,
            "operation": self.operation.value,
            "operation_intent_sha256": self.operation_intent_sha256,
            "authenticated_at": self.authenticated_at,
            "expires_at": self.expires_at,
        }


def load_principal_trust_policy(path: str | Path) -> PrincipalTrustPolicy:
    """Load one root-signed trust policy from strict JSON."""

    return PrincipalTrustPolicy.from_dict(_load_json_file(path, "principal trust policy"))


load_trust_policy = load_principal_trust_policy


def load_scope_grant(path: str | Path) -> ScopeGrant:
    """Load one signed scope grant from strict JSON."""

    return ScopeGrant.from_dict(_load_json_file(path, "scope grant"))


def load_scope_grant_revocation(
    path: str | Path,
) -> ScopeGrantRevocation:
    """Load one signed scope grant revocation from strict JSON."""

    return ScopeGrantRevocation.from_dict(
        _load_json_file(path, "scope grant revocation")
    )


def load_principal_assertion(path: str | Path) -> PrincipalAssertion:
    """Load one signed principal assertion from strict JSON."""

    return PrincipalAssertion.from_dict(_load_json_file(path, "principal assertion"))


def validate_operation_intent(
    operation: PrincipalOperation | str,
    intent: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate and normalize one closed, versioned mutation intent."""

    parsed_operation = _operation(
        operation.value if isinstance(operation, PrincipalOperation) else operation,
        "operation",
    )
    if not isinstance(intent, Mapping):
        raise _fail("operation intent must be an object")
    raw_intent = dict(intent)
    label = f"{parsed_operation.value} intent"

    if parsed_operation is PrincipalOperation.MISSION_CREATE:
        value = _object(
            raw_intent,
            label,
            {
                "mission_context_sha256",
                "mission_id",
                "principal_profile_id",
            },
        )
        return {
            "mission_context_sha256": _sha256(
                value["mission_context_sha256"],
                f"{label}.mission_context_sha256",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
        }

    if parsed_operation is PrincipalOperation.COLLABORATION_ACTIVATE:
        value = _object(
            raw_intent,
            label,
            {
                "mission_id",
                "plan_content_sha256",
                "plan_id",
                "principal_profile_id",
            },
        )
        return {
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "plan_content_sha256": _sha256(
                value["plan_content_sha256"],
                f"{label}.plan_content_sha256",
            ),
            "plan_id": _plan_id(
                value["plan_id"],
                f"{label}.plan_id",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
        }

    if parsed_operation in {
        PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
        PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
    }:
        value = _object(
            raw_intent,
            label,
            {
                "mission_id",
                "policy_selection_sha256",
                "principal_profile_id",
            },
        )
        return {
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "policy_selection_sha256": _sha256(
                value["policy_selection_sha256"],
                f"{label}.policy_selection_sha256",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
        }

    reviewer_admission_roles = {
        PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_OWNER_AUTHORIZE: "mission_owner",
        PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_CONTROL_APPROVE: (
            "independent_control"
        ),
    }
    if parsed_operation in reviewer_admission_roles:
        value = _object(
            raw_intent,
            label,
            {
                "mission_id",
                "mission_context_sha256",
                "admission_id",
                "admission_sha256",
                "principal_profile_id",
                "role",
            },
        )
        expected_role = reviewer_admission_roles[parsed_operation]
        if value["role"] != expected_role:
            raise _fail("Reviewer admission operation and role do not agree")
        admission_id = value["admission_id"]
        if (
            not isinstance(admission_id, str)
            or len(admission_id) != 36
            or not admission_id.startswith("RVA-")
            or re.fullmatch(r"[0-9A-F]{32}", admission_id[4:]) is None
        ):
            raise _fail("Reviewer admission identity is invalid")
        return {
            "mission_id": _mission_id(value["mission_id"], f"{label}.mission_id"),
            "mission_context_sha256": _sha256(
                value["mission_context_sha256"], f"{label}.mission_context_sha256"
            ),
            "admission_id": admission_id,
            "admission_sha256": _sha256(
                value["admission_sha256"], f"{label}.admission_sha256"
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"], f"{label}.principal_profile_id"
            ),
            "role": expected_role,
        }

    plan_replacement_roles = {
        PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_OWNER_AUTHORIZE: (
            "mission_owner",
            False,
        ),
        PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CONTROL_APPROVE: (
            "independent_control",
            False,
        ),
        PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CURRENT_OWNER_AUTHORIZE: (
            "current_owner",
            True,
        ),
        PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_PROPOSED_OWNER_ACCEPT: (
            "proposed_owner",
            True,
        ),
        PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_SOURCE_COMMAND_REVIEW: (
            "source_technical_command",
            True,
        ),
        PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_DESTINATION_COMMAND_REVIEW: (
            "destination_technical_command",
            True,
        ),
        PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CURRENT_OWNER_CANCEL: (
            "current_owner",
            True,
        ),
        PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_ASSURANCE_APPROVE: (
            "independent_assurance",
            False,
        ),
        PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_SECOND_CONTROL_APPROVE: (
            "second_control",
            False,
        ),
    }
    if parsed_operation in plan_replacement_roles:
        command_operations = {
            PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_SOURCE_COMMAND_REVIEW,
            PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_DESTINATION_COMMAND_REVIEW,
        }
        fields = {
            "authority_intent_sha256",
            "mission_id",
            "principal_profile_id",
            "prior_plan_id",
            "prior_plan_sha256",
            "replacement_plan_id",
            "replacement_plan_sha256",
            "role",
            "selection_sha256",
            "work_item_id",
        }
        if parsed_operation in command_operations:
            fields.add("command_authority_binding_sha256")
        value = _object(raw_intent, label, fields)
        expected_role, requires_work_item = plan_replacement_roles[parsed_operation]
        role = _identifier(value["role"], f"{label}.role")
        if role != expected_role:
            raise _fail(f"{label}.role does not match the operation")
        work_item_value = value["work_item_id"]
        if requires_work_item:
            work_item_id: str | None = _work_item_id(
                work_item_value,
                f"{label}.work_item_id",
            )
        elif work_item_value is not None:
            raise _fail(f"{label}.work_item_id must be null")
        else:
            work_item_id = None
        normalized = {
            "authority_intent_sha256": _sha256(
                value["authority_intent_sha256"],
                f"{label}.authority_intent_sha256",
            ),
            "mission_id": _mission_id(value["mission_id"], f"{label}.mission_id"),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "prior_plan_id": _plan_id(
                value["prior_plan_id"],
                f"{label}.prior_plan_id",
            ),
            "prior_plan_sha256": _sha256(
                value["prior_plan_sha256"],
                f"{label}.prior_plan_sha256",
            ),
            "replacement_plan_id": _plan_id(
                value["replacement_plan_id"],
                f"{label}.replacement_plan_id",
            ),
            "replacement_plan_sha256": _sha256(
                value["replacement_plan_sha256"],
                f"{label}.replacement_plan_sha256",
            ),
            "role": role,
            "selection_sha256": _sha256(
                value["selection_sha256"],
                f"{label}.selection_sha256",
            ),
            "work_item_id": work_item_id,
        }
        if parsed_operation in command_operations:
            normalized["command_authority_binding_sha256"] = _sha256(
                value["command_authority_binding_sha256"],
                f"{label}.command_authority_binding_sha256",
            )
        return normalized

    if parsed_operation in {
        PrincipalOperation.EXECUTION_CHANNEL_POLICY_OWNER_AUTHORIZE,
        PrincipalOperation.EXECUTION_CHANNEL_POLICY_CONTROL_APPROVE,
    }:
        value = _object(
            raw_intent,
            label,
            {
                "channel_policy_selection_sha256",
                "mission_id",
                "principal_profile_id",
            },
        )
        return {
            "channel_policy_selection_sha256": _sha256(
                value["channel_policy_selection_sha256"],
                f"{label}.channel_policy_selection_sha256",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
        }

    if parsed_operation is PrincipalOperation.EXECUTION_TRANSFER_REQUEST_AUTHORIZE:
        value = _object(
            raw_intent,
            label,
            {
                "mission_id",
                "principal_profile_id",
                "request_selection_sha256",
            },
        )
        return {
            "mission_id": _mission_id(value["mission_id"], f"{label}.mission_id"),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "request_selection_sha256": _sha256(
                value["request_selection_sha256"],
                f"{label}.request_selection_sha256",
            ),
        }

    if parsed_operation is PrincipalOperation.EXECUTION_TRANSFER_ACKNOWLEDGE:
        value = _object(
            raw_intent,
            label,
            {
                "acknowledgement_selection_sha256",
                "mission_id",
                "principal_profile_id",
                "request_id",
                "request_sha256",
            },
        )
        request_id = _identifier(value["request_id"], f"{label}.request_id")
        if re.fullmatch(r"ETR-[0-9A-F]{32}", request_id) is None:
            raise _fail(f"{label}.request_id is not a valid execution transfer request ID")
        return {
            "acknowledgement_selection_sha256": _sha256(
                value["acknowledgement_selection_sha256"],
                f"{label}.acknowledgement_selection_sha256",
            ),
            "mission_id": _mission_id(value["mission_id"], f"{label}.mission_id"),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "request_id": request_id,
            "request_sha256": _sha256(
                value["request_sha256"],
                f"{label}.request_sha256",
            ),
        }

    if parsed_operation is PrincipalOperation.EXECUTION_TIMEOUT_RESOLVE:
        value = _object(
            raw_intent,
            label,
            {
                "mission_id",
                "principal_profile_id",
                "resolution_selection_sha256",
            },
        )
        return {
            "mission_id": _mission_id(value["mission_id"], f"{label}.mission_id"),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "resolution_selection_sha256": _sha256(
                value["resolution_selection_sha256"],
                f"{label}.resolution_selection_sha256",
            ),
        }

    if parsed_operation in {
        PrincipalOperation.EXECUTION_SESSION_ACTIVATE_AUTHORIZE,
        PrincipalOperation.EXECUTION_SESSION_ACTIVATE_ACCEPT,
    }:
        value = _object(
            raw_intent,
            label,
            {
                "activation_selection_sha256",
                "mission_id",
                "principal_profile_id",
            },
        )
        return {
            "activation_selection_sha256": _sha256(
                value["activation_selection_sha256"],
                f"{label}.activation_selection_sha256",
            ),
            "mission_id": _mission_id(value["mission_id"], f"{label}.mission_id"),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
        }

    if parsed_operation is PrincipalOperation.EXECUTION_SESSION_REVOKE:
        value = _object(
            raw_intent,
            label,
            {
                "mission_id",
                "principal_profile_id",
                "revocation_selection_sha256",
            },
        )
        return {
            "mission_id": _mission_id(value["mission_id"], f"{label}.mission_id"),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "revocation_selection_sha256": _sha256(
                value["revocation_selection_sha256"],
                f"{label}.revocation_selection_sha256",
            ),
        }

    if parsed_operation in {
        PrincipalOperation.EXECUTOR_ACKNOWLEDGE,
        PrincipalOperation.EXECUTOR_ACKNOWLEDGE_SAFETY,
    }:
        value = _object(
            raw_intent,
            label,
            {
                "acknowledgement_selection_sha256",
                "dispatch_sha256",
                "mission_id",
                "principal_profile_id",
            },
        )
        return {
            "acknowledgement_selection_sha256": _sha256(
                value["acknowledgement_selection_sha256"],
                f"{label}.acknowledgement_selection_sha256",
            ),
            "dispatch_sha256": _sha256(
                value["dispatch_sha256"],
                f"{label}.dispatch_sha256",
            ),
            "mission_id": _mission_id(value["mission_id"], f"{label}.mission_id"),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
        }

    if parsed_operation is PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE:
        value = _object(
            raw_intent,
            label,
            {
                "ingest_receipt_selection_sha256",
                "ingest_request_sha256",
                "lifecycle_policy_sha256",
                "mission_id",
                "principal_profile_id",
            },
        )
        return {
            "ingest_receipt_selection_sha256": _sha256(
                value["ingest_receipt_selection_sha256"],
                f"{label}.ingest_receipt_selection_sha256",
            ),
            "ingest_request_sha256": _sha256(
                value["ingest_request_sha256"],
                f"{label}.ingest_request_sha256",
            ),
            "lifecycle_policy_sha256": _sha256(
                value["lifecycle_policy_sha256"],
                f"{label}.lifecycle_policy_sha256",
            ),
            "mission_id": _mission_id(value["mission_id"], f"{label}.mission_id"),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
        }

    if parsed_operation in {
        PrincipalOperation.EXECUTOR_DISPATCH_AUTHORIZE,
        PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE,
    }:
        value = _object(
            raw_intent,
            label,
            {
                "dispatch_selection_sha256",
                "mission_id",
                "principal_profile_id",
            },
        )
        return {
            "dispatch_selection_sha256": _sha256(
                value["dispatch_selection_sha256"],
                f"{label}.dispatch_selection_sha256",
            ),
            "mission_id": _mission_id(value["mission_id"], f"{label}.mission_id"),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
        }

    if parsed_operation in {
        PrincipalOperation.COLLABORATION_OWNERSHIP_CURRENT_OWNER_AUTHORIZE,
        PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT,
        PrincipalOperation.COLLABORATION_OWNERSHIP_CONTROL_APPROVE,
        PrincipalOperation.COLLABORATION_OWNERSHIP_SECOND_AUTHORITY_APPROVE,
    }:
        value = _object(
            raw_intent,
            label,
            {
                "entry_id",
                "entry_sha256",
                "mission_id",
                "preflight_id",
                "preflight_sha256",
                "principal_profile_id",
            },
        )
        return {
            "entry_id": _ownership_entry_id(
                value["entry_id"],
                f"{label}.entry_id",
            ),
            "entry_sha256": _sha256(
                value["entry_sha256"],
                f"{label}.entry_sha256",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "preflight_id": _ownership_preflight_id(
                value["preflight_id"],
                f"{label}.preflight_id",
            ),
            "preflight_sha256": _sha256(
                value["preflight_sha256"],
                f"{label}.preflight_sha256",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
        }

    if parsed_operation is PrincipalOperation.WORK_CLAIM:
        value = _object(
            raw_intent,
            label,
            {
                "expected_generation",
                "mission_id",
                "plan_content_sha256",
                "plan_id",
                "principal_profile_id",
                "work_item_id",
            },
        )
        return {
            "expected_generation": _non_negative_int(
                value["expected_generation"],
                f"{label}.expected_generation",
                maximum=6,
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "plan_content_sha256": _sha256(
                value["plan_content_sha256"],
                f"{label}.plan_content_sha256",
            ),
            "plan_id": _plan_id(
                value["plan_id"],
                f"{label}.plan_id",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "work_item_id": _work_item_id(
                value["work_item_id"],
                f"{label}.work_item_id",
            ),
        }

    if parsed_operation is PrincipalOperation.WORK_RENEW:
        value = _object(
            raw_intent,
            label,
            {
                "claim_generation",
                "expected_lease_expires_at",
                "mission_id",
                "plan_content_sha256",
                "plan_id",
                "previous_transition_id",
                "principal_profile_id",
                "work_item_id",
            },
        )
        return {
            "claim_generation": _positive_int(
                value["claim_generation"],
                f"{label}.claim_generation",
                maximum=6,
            ),
            "expected_lease_expires_at": _timestamp(
                value["expected_lease_expires_at"],
                f"{label}.expected_lease_expires_at",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "plan_content_sha256": _sha256(
                value["plan_content_sha256"],
                f"{label}.plan_content_sha256",
            ),
            "plan_id": _plan_id(
                value["plan_id"],
                f"{label}.plan_id",
            ),
            "previous_transition_id": _work_transition_id(
                value["previous_transition_id"],
                f"{label}.previous_transition_id",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "work_item_id": _work_item_id(
                value["work_item_id"],
                f"{label}.work_item_id",
            ),
        }

    if parsed_operation is PrincipalOperation.WORK_RELEASE:
        value = _object(
            raw_intent,
            label,
            {
                "claim_generation",
                "expected_lease_expires_at",
                "mission_id",
                "plan_content_sha256",
                "plan_id",
                "previous_transition_id",
                "principal_profile_id",
                "reason",
                "reason_code",
                "work_item_id",
            },
        )
        return {
            "claim_generation": _positive_int(
                value["claim_generation"],
                f"{label}.claim_generation",
                maximum=6,
            ),
            "expected_lease_expires_at": _timestamp(
                value["expected_lease_expires_at"],
                f"{label}.expected_lease_expires_at",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "plan_content_sha256": _sha256(
                value["plan_content_sha256"],
                f"{label}.plan_content_sha256",
            ),
            "plan_id": _plan_id(
                value["plan_id"],
                f"{label}.plan_id",
            ),
            "previous_transition_id": _work_transition_id(
                value["previous_transition_id"],
                f"{label}.previous_transition_id",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "reason": _intent_text(
                value["reason"],
                f"{label}.reason",
            ),
            "reason_code": _identifier(
                value["reason_code"],
                f"{label}.reason_code",
            ),
            "work_item_id": _work_item_id(
                value["work_item_id"],
                f"{label}.work_item_id",
            ),
        }

    if parsed_operation is PrincipalOperation.WORK_COMPLETE:
        value = _object(
            raw_intent,
            label,
            {
                "claim_generation",
                "evidence_manifest_sha256",
                "expected_lease_expires_at",
                "mission_id",
                "plan_content_sha256",
                "plan_id",
                "previous_transition_id",
                "principal_profile_id",
                "result_id",
                "result_sha256",
                "work_item_id",
            },
        )
        return {
            "claim_generation": _positive_int(
                value["claim_generation"],
                f"{label}.claim_generation",
                maximum=6,
            ),
            "evidence_manifest_sha256": _sha256(
                value["evidence_manifest_sha256"],
                f"{label}.evidence_manifest_sha256",
            ),
            "expected_lease_expires_at": _timestamp(
                value["expected_lease_expires_at"],
                f"{label}.expected_lease_expires_at",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "plan_content_sha256": _sha256(
                value["plan_content_sha256"],
                f"{label}.plan_content_sha256",
            ),
            "plan_id": _plan_id(
                value["plan_id"],
                f"{label}.plan_id",
            ),
            "previous_transition_id": _work_transition_id(
                value["previous_transition_id"],
                f"{label}.previous_transition_id",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "result_id": _identifier(
                value["result_id"],
                f"{label}.result_id",
            ),
            "result_sha256": _sha256(
                value["result_sha256"],
                f"{label}.result_sha256",
            ),
            "work_item_id": _work_item_id(
                value["work_item_id"],
                f"{label}.work_item_id",
            ),
        }

    if parsed_operation is PrincipalOperation.WORK_RECOVERY_REQUEST:
        value = _object(
            raw_intent,
            label,
            {
                "expected_generation",
                "expected_lease_expires_at",
                "mission_id",
                "plan_content_sha256",
                "plan_id",
                "previous_transition_id",
                "principal_profile_id",
                "reason",
                "reason_code",
                "remediation",
                "requested_attempts",
                "work_item_id",
            },
        )
        return {
            "expected_generation": _positive_int(
                value["expected_generation"],
                f"{label}.expected_generation",
                maximum=3,
            ),
            "expected_lease_expires_at": _timestamp(
                value["expected_lease_expires_at"],
                f"{label}.expected_lease_expires_at",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "plan_content_sha256": _sha256(
                value["plan_content_sha256"],
                f"{label}.plan_content_sha256",
            ),
            "plan_id": _plan_id(value["plan_id"], f"{label}.plan_id"),
            "previous_transition_id": _work_transition_id(
                value["previous_transition_id"],
                f"{label}.previous_transition_id",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "reason": _intent_text(value["reason"], f"{label}.reason"),
            "reason_code": _identifier(
                value["reason_code"],
                f"{label}.reason_code",
            ),
            "remediation": _intent_text(
                value["remediation"],
                f"{label}.remediation",
            ),
            "requested_attempts": _positive_int(
                value["requested_attempts"],
                f"{label}.requested_attempts",
                maximum=3,
            ),
            "work_item_id": _work_item_id(
                value["work_item_id"],
                f"{label}.work_item_id",
            ),
        }

    if parsed_operation is PrincipalOperation.WORK_RECOVERY_APPROVE:
        value = _object(
            raw_intent,
            label,
            {
                "additional_attempts",
                "authority",
                "constraints",
                "decision_owner",
                "mission_id",
                "owner_profile_id",
                "plan_content_sha256",
                "plan_id",
                "principal_profile_id",
                "recovery_epoch",
                "recovery_request_id",
                "recovery_request_sha256",
                "work_item_id",
            },
        )
        return {
            "additional_attempts": _positive_int(
                value["additional_attempts"],
                f"{label}.additional_attempts",
                maximum=3,
            ),
            "authority": _intent_text(
                value["authority"],
                f"{label}.authority",
            ),
            "constraints": _intent_constraints(
                value["constraints"],
                f"{label}.constraints",
            ),
            "decision_owner": _identifier(
                value["decision_owner"],
                f"{label}.decision_owner",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "owner_profile_id": _profile_id(
                value["owner_profile_id"],
                f"{label}.owner_profile_id",
            ),
            "plan_content_sha256": _sha256(
                value["plan_content_sha256"],
                f"{label}.plan_content_sha256",
            ),
            "plan_id": _plan_id(value["plan_id"], f"{label}.plan_id"),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "recovery_epoch": _positive_int(
                value["recovery_epoch"],
                f"{label}.recovery_epoch",
                maximum=2_147_483_647,
            ),
            "recovery_request_id": _work_recovery_request_id(
                value["recovery_request_id"],
                f"{label}.recovery_request_id",
            ),
            "recovery_request_sha256": _sha256(
                value["recovery_request_sha256"],
                f"{label}.recovery_request_sha256",
            ),
            "work_item_id": _work_item_id(
                value["work_item_id"],
                f"{label}.work_item_id",
            ),
        }

    if parsed_operation is PrincipalOperation.WORK_RECOVERY_DENY:
        value = _object(
            raw_intent,
            label,
            {
                "additional_attempts",
                "decision_owner",
                "mission_id",
                "owner_profile_id",
                "plan_content_sha256",
                "plan_id",
                "principal_profile_id",
                "reason",
                "reason_code",
                "recovery_epoch",
                "recovery_request_id",
                "recovery_request_sha256",
                "risk",
                "work_item_id",
            },
        )
        return {
            "additional_attempts": _positive_int(
                value["additional_attempts"],
                f"{label}.additional_attempts",
                maximum=3,
            ),
            "decision_owner": _identifier(
                value["decision_owner"],
                f"{label}.decision_owner",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "owner_profile_id": _profile_id(
                value["owner_profile_id"],
                f"{label}.owner_profile_id",
            ),
            "plan_content_sha256": _sha256(
                value["plan_content_sha256"],
                f"{label}.plan_content_sha256",
            ),
            "plan_id": _plan_id(value["plan_id"], f"{label}.plan_id"),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "reason": _intent_text(value["reason"], f"{label}.reason"),
            "reason_code": _identifier(
                value["reason_code"],
                f"{label}.reason_code",
            ),
            "recovery_epoch": _positive_int(
                value["recovery_epoch"],
                f"{label}.recovery_epoch",
                maximum=2_147_483_647,
            ),
            "recovery_request_id": _work_recovery_request_id(
                value["recovery_request_id"],
                f"{label}.recovery_request_id",
            ),
            "recovery_request_sha256": _sha256(
                value["recovery_request_sha256"],
                f"{label}.recovery_request_sha256",
            ),
            "risk": _intent_text(value["risk"], f"{label}.risk"),
            "work_item_id": _work_item_id(
                value["work_item_id"],
                f"{label}.work_item_id",
            ),
        }

    if parsed_operation is PrincipalOperation.WORK_CANCEL:
        value = _object(
            raw_intent,
            label,
            {
                "affected_work_item_ids",
                "cancellation_scope",
                "decision_owner",
                "expected_generation",
                "expected_lease_expires_at",
                "mission_id",
                "owner_profile_id",
                "plan_content_sha256",
                "plan_id",
                "previous_transition_id",
                "principal_profile_id",
                "reason",
                "reason_code",
                "risk",
                "work_item_id",
            },
        )
        expected_generation = _non_negative_int(
            value["expected_generation"],
            f"{label}.expected_generation",
            maximum=6,
        )
        previous_transition_id = (
            None
            if value["previous_transition_id"] is None
            else _work_transition_id(
                value["previous_transition_id"],
                f"{label}.previous_transition_id",
            )
        )
        expected_lease_expires_at = (
            None
            if value["expected_lease_expires_at"] is None
            else _timestamp(
                value["expected_lease_expires_at"],
                f"{label}.expected_lease_expires_at",
            )
        )
        cancellation_scope = _intent_text(
            value["cancellation_scope"],
            f"{label}.cancellation_scope",
        )
        work_item_id = _work_item_id(
            value["work_item_id"],
            f"{label}.work_item_id",
        )
        affected_work_item_ids = _work_item_ids(
            value["affected_work_item_ids"],
            f"{label}.affected_work_item_ids",
        )
        return {
            "affected_work_item_ids": affected_work_item_ids,
            "cancellation_scope": cancellation_scope,
            "decision_owner": _identifier(
                value["decision_owner"],
                f"{label}.decision_owner",
            ),
            "expected_generation": expected_generation,
            "expected_lease_expires_at": expected_lease_expires_at,
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "owner_profile_id": _profile_id(
                value["owner_profile_id"],
                f"{label}.owner_profile_id",
            ),
            "plan_content_sha256": _sha256(
                value["plan_content_sha256"],
                f"{label}.plan_content_sha256",
            ),
            "plan_id": _plan_id(value["plan_id"], f"{label}.plan_id"),
            "previous_transition_id": previous_transition_id,
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "reason": _intent_text(
                value["reason"],
                f"{label}.reason",
            ),
            "reason_code": _identifier(
                value["reason_code"],
                f"{label}.reason_code",
            ),
            "risk": _intent_text(value["risk"], f"{label}.risk"),
            "work_item_id": work_item_id,
        }

    if parsed_operation in {
        PrincipalOperation.WORK_HANDOFF_AUTHORIZE,
        PrincipalOperation.WORK_HANDOFF_ACCEPT,
    }:
        value = _object(
            raw_intent,
            label,
            {
                "candidate_assertion_id",
                "candidate_issuer",
                "candidate_profile_id",
                "candidate_profile_version",
                "candidate_registry_status",
                "expected_generation",
                "expected_lease_expires_at",
                "handoff_scope",
                "mission_id",
                "owner_assertion_id",
                "owner_issuer",
                "plan_content_sha256",
                "plan_id",
                "planned_owner_profile_id",
                "previous_transition_id",
                "principal_profile_id",
                "qualification_basis",
                "qualification_command_id",
                "reason",
                "reason_code",
                "work_item_id",
                "work_item_kind",
            },
        )
        expected_generation = _non_negative_int(
            value["expected_generation"],
            f"{label}.expected_generation",
            maximum=3,
        )
        previous_transition_id = (
            None
            if value["previous_transition_id"] is None
            else _work_transition_id(
                value["previous_transition_id"],
                f"{label}.previous_transition_id",
            )
        )
        expected_lease_expires_at = (
            None
            if value["expected_lease_expires_at"] is None
            else _timestamp(
                value["expected_lease_expires_at"],
                f"{label}.expected_lease_expires_at",
            )
        )
        return {
            "candidate_assertion_id": _assertion_id(
                value["candidate_assertion_id"],
                f"{label}.candidate_assertion_id",
            ),
            "candidate_issuer": _identifier(
                value["candidate_issuer"],
                f"{label}.candidate_issuer",
            ),
            "candidate_profile_id": _profile_id(
                value["candidate_profile_id"],
                f"{label}.candidate_profile_id",
            ),
            "candidate_profile_version": _identifier(
                value["candidate_profile_version"],
                f"{label}.candidate_profile_version",
            ),
            "candidate_registry_status": _identifier(
                value["candidate_registry_status"],
                f"{label}.candidate_registry_status",
            ),
            "expected_generation": expected_generation,
            "expected_lease_expires_at": expected_lease_expires_at,
            "handoff_scope": _intent_text(
                value["handoff_scope"],
                f"{label}.handoff_scope",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "owner_assertion_id": _assertion_id(
                value["owner_assertion_id"],
                f"{label}.owner_assertion_id",
            ),
            "owner_issuer": _identifier(
                value["owner_issuer"],
                f"{label}.owner_issuer",
            ),
            "plan_content_sha256": _sha256(
                value["plan_content_sha256"],
                f"{label}.plan_content_sha256",
            ),
            "plan_id": _plan_id(value["plan_id"], f"{label}.plan_id"),
            "planned_owner_profile_id": _profile_id(
                value["planned_owner_profile_id"],
                f"{label}.planned_owner_profile_id",
            ),
            "previous_transition_id": previous_transition_id,
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "qualification_basis": _intent_text(
                value["qualification_basis"],
                f"{label}.qualification_basis",
            ),
            "qualification_command_id": _identifier(
                value["qualification_command_id"],
                f"{label}.qualification_command_id",
            ),
            "reason": _intent_text(
                value["reason"],
                f"{label}.reason",
            ),
            "reason_code": _identifier(
                value["reason_code"],
                f"{label}.reason_code",
            ),
            "work_item_id": _work_item_id(
                value["work_item_id"],
                f"{label}.work_item_id",
            ),
            "work_item_kind": _identifier(
                value["work_item_kind"],
                f"{label}.work_item_kind",
            ),
        }

    if parsed_operation is PrincipalOperation.EVENT_APPEND:
        value = _object(
            raw_intent,
            label,
            {
                "event_batch_sha256",
                "expected_revision",
                "mission_id",
                "principal_profile_id",
            },
        )
        return {
            "event_batch_sha256": _sha256(
                value["event_batch_sha256"],
                f"{label}.event_batch_sha256",
            ),
            "expected_revision": _non_negative_int_or_none(
                value["expected_revision"],
                f"{label}.expected_revision",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
        }

    if parsed_operation is PrincipalOperation.APPROVAL_SUBMIT:
        value = _object(
            raw_intent,
            label,
            {
                "executor_profile_id",
                "idempotency_key_sha256",
                "mission_id",
                "principal_profile_id",
                "proposal_id",
                "review_expires_at",
            },
        )
        return {
            "executor_profile_id": _profile_id(
                value["executor_profile_id"],
                f"{label}.executor_profile_id",
            ),
            "idempotency_key_sha256": _sha256(
                value["idempotency_key_sha256"],
                f"{label}.idempotency_key_sha256",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "proposal_id": _event_id(
                value["proposal_id"],
                f"{label}.proposal_id",
            ),
            "review_expires_at": _timestamp(
                value["review_expires_at"],
                f"{label}.review_expires_at",
            ),
        }

    if parsed_operation is PrincipalOperation.APPROVAL_APPROVE:
        value = _object(
            raw_intent,
            label,
            {
                "approval_id",
                "authority",
                "authorization_expires_at",
                "constraints",
                "expected_version",
                "idempotency_key_sha256",
                "principal_profile_id",
            },
        )
        return {
            "approval_id": _approval_id(
                value["approval_id"],
                f"{label}.approval_id",
            ),
            "authority": _intent_text(
                value["authority"],
                f"{label}.authority",
            ),
            "authorization_expires_at": _timestamp(
                value["authorization_expires_at"],
                f"{label}.authorization_expires_at",
            ),
            "constraints": _intent_constraints(
                value["constraints"],
                f"{label}.constraints",
            ),
            "expected_version": _positive_int(
                value["expected_version"],
                f"{label}.expected_version",
                maximum=2_147_483_647,
            ),
            "idempotency_key_sha256": _sha256(
                value["idempotency_key_sha256"],
                f"{label}.idempotency_key_sha256",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
        }

    if parsed_operation in {
        PrincipalOperation.APPROVAL_DENY,
        PrincipalOperation.APPROVAL_REVOKE,
    }:
        value = _object(
            raw_intent,
            label,
            {
                "approval_id",
                "decision_owner",
                "expected_version",
                "idempotency_key_sha256",
                "principal_profile_id",
                "reason",
                "reason_code",
                "risk",
            },
        )
        return {
            "approval_id": _approval_id(
                value["approval_id"],
                f"{label}.approval_id",
            ),
            "decision_owner": _intent_text(
                value["decision_owner"],
                f"{label}.decision_owner",
            ),
            "expected_version": _positive_int(
                value["expected_version"],
                f"{label}.expected_version",
                maximum=2_147_483_647,
            ),
            "idempotency_key_sha256": _sha256(
                value["idempotency_key_sha256"],
                f"{label}.idempotency_key_sha256",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "reason": _intent_text(
                value["reason"],
                f"{label}.reason",
            ),
            "reason_code": _identifier(
                value["reason_code"],
                f"{label}.reason_code",
            ),
            "risk": _intent_text(
                value["risk"],
                f"{label}.risk",
            ),
        }

    if parsed_operation is PrincipalOperation.MISSION_STOP:
        value = _object(
            raw_intent,
            label,
            {
                "decision_owner",
                "expected_version",
                "idempotency_key_sha256",
                "mission_id",
                "principal_profile_id",
                "reason",
                "reason_code",
                "risk",
            },
        )
        return {
            "decision_owner": _intent_text(
                value["decision_owner"],
                f"{label}.decision_owner",
            ),
            "expected_version": _positive_int(
                value["expected_version"],
                f"{label}.expected_version",
                maximum=2_147_483_647,
            ),
            "idempotency_key_sha256": _sha256(
                value["idempotency_key_sha256"],
                f"{label}.idempotency_key_sha256",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "reason": _intent_text(
                value["reason"],
                f"{label}.reason",
            ),
            "reason_code": _identifier(
                value["reason_code"],
                f"{label}.reason_code",
            ),
            "risk": _intent_text(
                value["risk"],
                f"{label}.risk",
            ),
        }

    if parsed_operation is PrincipalOperation.SIMULATION_RUN:
        value = _object(
            raw_intent,
            label,
            {
                "approval_id",
                "idempotency_key_sha256",
                "principal_profile_id",
            },
        )
        return {
            "approval_id": _approval_id(
                value["approval_id"],
                f"{label}.approval_id",
            ),
            "idempotency_key_sha256": _sha256(
                value["idempotency_key_sha256"],
                f"{label}.idempotency_key_sha256",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
        }

    if parsed_operation is PrincipalOperation.MODEL_EXECUTE:
        value = _object(
            raw_intent,
            label,
            {
                "execution_admission_core_sha256",
                "mission_id",
                "principal_profile_id",
            },
        )
        return {
            "execution_admission_core_sha256": _sha256(
                value["execution_admission_core_sha256"],
                f"{label}.execution_admission_core_sha256",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
        }

    if parsed_operation is PrincipalOperation.TARGET_HEALTH_GATE_RESUME:
        value = _object(
            raw_intent,
            label,
            {
                "idempotency_key_sha256",
                "mission_id",
                "principal_profile_id",
                "recovery_intent_sha256",
                "role",
            },
        )
        role = _identifier(value["role"], f"{label}.role")
        if role != "independent_control":
            raise _fail(f"{label}.role is invalid")
        return {
            "idempotency_key_sha256": _sha256(
                value["idempotency_key_sha256"],
                f"{label}.idempotency_key_sha256",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "recovery_intent_sha256": _sha256(
                value["recovery_intent_sha256"],
                f"{label}.recovery_intent_sha256",
            ),
            "role": role,
        }

    if parsed_operation in {
        PrincipalOperation.ACTION_RESOLVE,
        PrincipalOperation.ACTION_QUORUM_AUTHORIZE,
        PrincipalOperation.ACTION_ADMIT,
        PrincipalOperation.ACTION_ADMISSION_REVOKE,
        PrincipalOperation.ACTION_EXECUTE,
        PrincipalOperation.ACTION_EXECUTION_RECONCILE,
    }:
        value = _object(
            raw_intent,
            label,
            {
                "action_intent_sha256",
                "idempotency_key_sha256",
                "mission_id",
                "principal_profile_id",
                "role",
            },
        )
        role = _identifier(value["role"], f"{label}.role")
        if role not in {
            "typed_resolver",
            "mission_owner",
            "independent_control",
            "admission_control",
        }:
            raise _fail(f"{label}.role is invalid")
        return {
            "action_intent_sha256": _sha256(
                value["action_intent_sha256"],
                f"{label}.action_intent_sha256",
            ),
            "idempotency_key_sha256": _sha256(
                value["idempotency_key_sha256"],
                f"{label}.idempotency_key_sha256",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "role": role,
        }

    if parsed_operation is PrincipalOperation.ACTION_AUTHORITY_PUBLISH:
        value = _object(
            raw_intent,
            label,
            {
                "idempotency_key_sha256",
                "mission_id",
                "principal_profile_id",
                "publication_sha256",
            },
        )
        return {
            "idempotency_key_sha256": _sha256(
                value["idempotency_key_sha256"],
                f"{label}.idempotency_key_sha256",
            ),
            "mission_id": _mission_id(
                value["mission_id"],
                f"{label}.mission_id",
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"],
                f"{label}.principal_profile_id",
            ),
            "publication_sha256": _sha256(
                value["publication_sha256"],
                f"{label}.publication_sha256",
            ),
        }

    if parsed_operation is PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER:
        value = _object(
            raw_intent,
            label,
            {
                "active_plan_id",
                "active_plan_sha256",
                "active_plan_version",
                "mission_id",
                "mission_revision",
                "principal_profile_id",
                "snapshot_id",
                "snapshot_sha256",
                "workspace_event_count",
                "workspace_event_head_sha256",
                "workspace_id",
                "workspace_revision",
                "workspace_schema_version",
                "workspace_sha256",
            },
        )
        return {
            "active_plan_id": _plan_id(value["active_plan_id"], f"{label}.active_plan_id"),
            "active_plan_sha256": _sha256(
                value["active_plan_sha256"], f"{label}.active_plan_sha256"
            ),
            "active_plan_version": _positive_int(
                value["active_plan_version"],
                f"{label}.active_plan_version",
                maximum=2_147_483_647,
            ),
            "mission_id": _mission_id(value["mission_id"], f"{label}.mission_id"),
            "mission_revision": _non_negative_int(
                value["mission_revision"],
                f"{label}.mission_revision",
                maximum=2_147_483_647,
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"], f"{label}.principal_profile_id"
            ),
            "snapshot_id": _identifier(value["snapshot_id"], f"{label}.snapshot_id"),
            "snapshot_sha256": _sha256(
                value["snapshot_sha256"], f"{label}.snapshot_sha256"
            ),
            "workspace_event_count": _positive_int(
                value["workspace_event_count"],
                f"{label}.workspace_event_count",
                maximum=2_147_483_647,
            ),
            "workspace_event_head_sha256": _sha256(
                value["workspace_event_head_sha256"],
                f"{label}.workspace_event_head_sha256",
            ),
            "workspace_id": _identifier(
                value["workspace_id"], f"{label}.workspace_id"
            ),
            "workspace_revision": _non_negative_int(
                value["workspace_revision"],
                f"{label}.workspace_revision",
                maximum=2_147_483_647,
            ),
            "workspace_schema_version": _positive_int(
                value["workspace_schema_version"],
                f"{label}.workspace_schema_version",
                maximum=2_147_483_647,
            ),
            "workspace_sha256": _sha256(
                value["workspace_sha256"], f"{label}.workspace_sha256"
            ),
        }

    if parsed_operation is PrincipalOperation.EXPERT_WORK_PRODUCT_REVIEW:
        value = _object(
            raw_intent,
            label,
            {
                "active_plan_id",
                "active_plan_sha256",
                "active_plan_version",
                "mission_id",
                "mission_revision",
                "principal_profile_id",
                "product_id",
                "product_sha256",
                "reviewer_role",
                "snapshot_id",
                "snapshot_sha256",
                "submission_id",
                "submission_sha256",
                "work_id",
            },
        )
        reviewer_role = _identifier(
            value["reviewer_role"], f"{label}.reviewer_role"
        )
        if reviewer_role not in {
            "technical_evaluator",
            "independent_control",
            "independent_assurance",
        }:
            raise _fail(f"{label}.reviewer_role is invalid")
        return {
            "active_plan_id": _plan_id(value["active_plan_id"], f"{label}.active_plan_id"),
            "active_plan_sha256": _sha256(
                value["active_plan_sha256"], f"{label}.active_plan_sha256"
            ),
            "active_plan_version": _positive_int(
                value["active_plan_version"],
                f"{label}.active_plan_version",
                maximum=2_147_483_647,
            ),
            "mission_id": _mission_id(value["mission_id"], f"{label}.mission_id"),
            "mission_revision": _non_negative_int(
                value["mission_revision"],
                f"{label}.mission_revision",
                maximum=2_147_483_647,
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"], f"{label}.principal_profile_id"
            ),
            "product_id": _identifier(value["product_id"], f"{label}.product_id"),
            "product_sha256": _sha256(
                value["product_sha256"], f"{label}.product_sha256"
            ),
            "reviewer_role": reviewer_role,
            "snapshot_id": _identifier(value["snapshot_id"], f"{label}.snapshot_id"),
            "snapshot_sha256": _sha256(
                value["snapshot_sha256"], f"{label}.snapshot_sha256"
            ),
            "submission_id": _identifier(
                value["submission_id"], f"{label}.submission_id"
            ),
            "submission_sha256": _sha256(
                value["submission_sha256"], f"{label}.submission_sha256"
            ),
            "work_id": _identifier(value["work_id"], f"{label}.work_id"),
        }

    if parsed_operation is PrincipalOperation.EXPERT_WORKSPACE_REVIEW_CLOSE:
        value = _object(
            raw_intent,
            label,
            {
                "active_plan_id",
                "active_plan_sha256",
                "active_plan_version",
                "closure_request_id",
                "closure_request_sha256",
                "expected_disposition",
                "mission_id",
                "mission_revision",
                "principal_profile_id",
                "review_set_sha256",
                "snapshot_id",
                "snapshot_sha256",
            },
        )
        disposition = _identifier(
            value["expected_disposition"], f"{label}.expected_disposition"
        )
        if disposition not in {"accepted", "rejected", "rework_required"}:
            raise _fail(f"{label}.expected_disposition is invalid")
        return {
            "active_plan_id": _plan_id(value["active_plan_id"], f"{label}.active_plan_id"),
            "active_plan_sha256": _sha256(
                value["active_plan_sha256"], f"{label}.active_plan_sha256"
            ),
            "active_plan_version": _positive_int(
                value["active_plan_version"],
                f"{label}.active_plan_version",
                maximum=2_147_483_647,
            ),
            "closure_request_id": _identifier(
                value["closure_request_id"], f"{label}.closure_request_id"
            ),
            "closure_request_sha256": _sha256(
                value["closure_request_sha256"],
                f"{label}.closure_request_sha256",
            ),
            "expected_disposition": disposition,
            "mission_id": _mission_id(value["mission_id"], f"{label}.mission_id"),
            "mission_revision": _non_negative_int(
                value["mission_revision"],
                f"{label}.mission_revision",
                maximum=2_147_483_647,
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"], f"{label}.principal_profile_id"
            ),
            "review_set_sha256": _sha256(
                value["review_set_sha256"], f"{label}.review_set_sha256"
            ),
            "snapshot_id": _identifier(value["snapshot_id"], f"{label}.snapshot_id"),
            "snapshot_sha256": _sha256(
                value["snapshot_sha256"], f"{label}.snapshot_sha256"
            ),
        }

    if parsed_operation is PrincipalOperation.EXPERT_WORKSPACE_REVIEW_REVOKE:
        value = _object(
            raw_intent,
            label,
            {
                "active_plan_id",
                "active_plan_sha256",
                "active_plan_version",
                "closure_id",
                "closure_sha256",
                "mission_id",
                "mission_revision",
                "principal_profile_id",
                "reason_code",
                "revocation_core_sha256",
            },
        )
        return {
            "active_plan_id": _plan_id(value["active_plan_id"], f"{label}.active_plan_id"),
            "active_plan_sha256": _sha256(
                value["active_plan_sha256"], f"{label}.active_plan_sha256"
            ),
            "active_plan_version": _positive_int(
                value["active_plan_version"],
                f"{label}.active_plan_version",
                maximum=2_147_483_647,
            ),
            "closure_id": _identifier(value["closure_id"], f"{label}.closure_id"),
            "closure_sha256": _sha256(
                value["closure_sha256"], f"{label}.closure_sha256"
            ),
            "mission_id": _mission_id(value["mission_id"], f"{label}.mission_id"),
            "mission_revision": _non_negative_int(
                value["mission_revision"],
                f"{label}.mission_revision",
                maximum=2_147_483_647,
            ),
            "principal_profile_id": _profile_id(
                value["principal_profile_id"], f"{label}.principal_profile_id"
            ),
            "reason_code": _identifier(value["reason_code"], f"{label}.reason_code"),
            "revocation_core_sha256": _sha256(
                value["revocation_core_sha256"], f"{label}.revocation_core_sha256"
            ),
        }

    raise _fail("operation intent does not have a supported contract")


def compute_operation_intent_hash(
    operation: PrincipalOperation | str,
    intent: Mapping[str, Any],
) -> str:
    """Hash a validated operation request under a versioned domain."""

    parsed_operation = _operation(
        operation.value if isinstance(operation, PrincipalOperation) else operation,
        "operation",
    )
    normalized_intent = validate_operation_intent(
        parsed_operation,
        intent,
    )
    payload = {
        "operation": parsed_operation.value,
        "request": normalized_intent,
        "schema_version": 1,
    }
    return _hash_bytes(OPERATION_INTENT_HASH_DOMAIN + _canonical_json(payload).encode("ascii"))


def _root_public_key(
    trusted_root_keys: Mapping[str, bytes | Ed25519PublicKey],
    root_key_id: str,
) -> Ed25519PublicKey:
    if not isinstance(trusted_root_keys, Mapping):
        raise _fail("trusted_root_keys must be a mapping")
    try:
        candidate = trusted_root_keys[root_key_id]
    except KeyError as exc:
        raise _fail(f"Trust policy root key is not trusted: {root_key_id}") from exc
    return _strict_ed25519_public_key(
        candidate,
        f"Trusted root key {root_key_id}",
    )


def verify_trust_policy(
    policy: PrincipalTrustPolicy,
    trusted_root_keys: Mapping[str, bytes | Ed25519PublicKey],
    *,
    expected_audience: str,
    expected_store_id: str,
    expected_root_key_id: str,
    minimum_policy_version: int,
    clock: Callable[[], datetime],
) -> VerifiedTrustPolicy:
    """Verify a policy against a separately configured root public key."""

    if not isinstance(policy, PrincipalTrustPolicy):
        raise _fail("policy must be a PrincipalTrustPolicy")
    policy = PrincipalTrustPolicy.from_dict(policy.to_dict())
    audience = _identifier(expected_audience, "expected_audience")
    store_id = _store_id(expected_store_id, "expected_store_id")
    root_key_id = _identifier(
        expected_root_key_id,
        "expected_root_key_id",
    )
    minimum_version = _policy_version(
        minimum_policy_version,
        "minimum_policy_version",
    )
    if policy.audience != audience:
        raise _fail("Trust policy audience does not match the runtime audience")
    if policy.store_id != store_id:
        raise _fail("Trust policy store does not match the runtime store")
    if policy.root_key_id != root_key_id:
        raise _fail("Trust policy root key does not match the expected root")
    if policy.policy_version < minimum_version:
        raise _fail("Trust policy version is older than the required minimum")
    now = _clock_value(clock)
    _verify_window(
        issued_at=policy.issued_at,
        not_before=policy.not_before,
        expires_at=policy.expires_at,
        now=now,
        label="principal trust policy",
    )
    root = _root_public_key(trusted_root_keys, root_key_id)
    root_bytes = root.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    for key in policy.keys:
        if key.key_id == root_key_id:
            raise _fail("Trust policy key ID must not reuse the root key ID")
        if hmac.compare_digest(
            _decode_base64url(key.public_key),
            root_bytes,
        ):
            raise _fail(
                "Trust policy issuer keys must not reuse root key material"
            )
    _verify_ed25519(root, policy.signature, policy.signing_bytes(), "Trust policy")
    verified_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    policy_sha256 = policy.content_sha256
    return VerifiedTrustPolicy(
        policy=policy,
        policy_sha256=policy_sha256,
        verified_at=verified_at,
        _proof=_verification_proof(
            "verified_trust_policy",
            {
                "policy": policy.to_dict(),
                "policy_sha256": policy_sha256,
                "verified_at": verified_at,
            },
        ),
    )


def _verify_policy_key(
    verified_policy: VerifiedTrustPolicy,
    *,
    key_id: str,
    required_key_use: TrustKeyUse,
    issuer: str,
    profile_id: str,
    subject: str,
    operations: Sequence[PrincipalOperation],
    issued_at: str,
    now: datetime,
) -> TrustKey:
    if not isinstance(verified_policy, VerifiedTrustPolicy):
        raise _fail("A root-verified trust policy is required")
    policy = verified_policy.policy
    key = policy.key(key_id)
    if key.key_use is not required_key_use:
        raise _fail(
            f"Trust key {key.key_id} cannot verify a {required_key_use.value} credential"
        )
    if key.state is TrustKeyState.REVOKED:
        raise _fail(f"Trust key {key.key_id} is revoked")
    if issuer != key.issuer:
        raise _fail("Credential issuer does not match its trust key")
    issued = _parse_timestamp(issued_at)
    key_start = _parse_timestamp(key.not_before)
    key_end = _parse_timestamp(key.not_after)
    if not key_start <= issued < key_end:
        raise _fail(f"Credential was issued outside trust key {key.key_id} validity")
    if not key_start <= now < key_end:
        raise _fail(f"Trust key {key.key_id} is not currently valid")
    if key.state is TrustKeyState.RETIRING:
        assert key.retire_at is not None
        retirement = _parse_timestamp(key.retire_at)
        if issued >= retirement:
            raise _fail(
                f"Credential was issued at or after trust key {key.key_id} retirement"
            )
        if now >= retirement:
            raise _fail(
                f"Trust key {key.key_id} has reached its retirement cutoff"
            )
    if profile_id not in policy.allowed_profiles or profile_id not in key.allowed_profiles:
        raise _fail("Credential profile is not exactly allowed by policy and key")
    if subject not in policy.allowed_subjects or subject not in key.allowed_subjects:
        raise _fail("Credential subject is not exactly allowed by policy and key")
    for operation in operations:
        if operation not in policy.allowed_operations or operation not in key.allowed_operations:
            raise _fail("Credential operation is not exactly allowed by policy and key")
    return key


def verify_scope_grant(
    grant: ScopeGrant,
    verified_policy: VerifiedTrustPolicy,
    *,
    expected_audience: str,
    expected_store_id: str,
    expected_mission_id: str,
    expected_mission_context_hash: str,
    expected_scope_reference: str,
    expected_scope_document_hash: str,
    expected_environment: MissionEnvironment | str,
    expected_max_action_tier: ActionTier | str,
    expected_constraints_hash: str,
    expected_operation: PrincipalOperation | str,
    allow_expired_for_safety_reduction: bool = False,
    clock: Callable[[], datetime],
) -> VerifiedScopeGrant:
    """Verify a scope signature, lifetime, principal, and mission binding."""

    if not isinstance(grant, ScopeGrant):
        raise _fail("grant must be a ScopeGrant")
    grant = ScopeGrant.from_dict(grant.to_dict())
    if not isinstance(verified_policy, VerifiedTrustPolicy):
        raise _fail("verified_policy must be a VerifiedTrustPolicy")
    if not verified_policy._proof_is_valid():
        raise _fail("verified_policy was not produced by verify_trust_policy")
    audience = _identifier(expected_audience, "expected_audience")
    store_id = _store_id(expected_store_id, "expected_store_id")
    mission_id = _mission_id(expected_mission_id, "expected_mission_id")
    mission_context_hash = _sha256(
        expected_mission_context_hash,
        "expected_mission_context_hash",
    )
    scope_reference = _ascii_text(
        expected_scope_reference,
        "expected_scope_reference",
        maximum=512,
    )
    scope_document_hash = _sha256(
        expected_scope_document_hash,
        "expected_scope_document_hash",
    )
    environment = _environment(
        expected_environment.value
        if isinstance(expected_environment, MissionEnvironment)
        else expected_environment,
        "expected_environment",
    )
    max_action_tier = _action_tier(
        expected_max_action_tier.value
        if isinstance(expected_max_action_tier, ActionTier)
        else expected_max_action_tier,
        "expected_max_action_tier",
    )
    constraints_hash = _sha256(
        expected_constraints_hash,
        "expected_constraints_hash",
    )
    operation = _operation(
        expected_operation.value
        if isinstance(expected_operation, PrincipalOperation)
        else expected_operation,
        "expected_operation",
    )
    if not isinstance(allow_expired_for_safety_reduction, bool):
        raise _fail("allow_expired_for_safety_reduction must be a boolean")
    if grant.policy_id != verified_policy.policy.policy_id:
        raise _fail("Scope grant policy does not match the verified trust policy")
    if grant.policy_version != verified_policy.policy.policy_version:
        raise _fail("Scope grant policy version does not match the verified trust policy")
    if grant.audience != audience or grant.audience != verified_policy.policy.audience:
        raise _fail("Scope grant audience does not match")
    if grant.store_id != store_id:
        raise _fail("Scope grant store does not match")
    if grant.mission_id != mission_id:
        raise _fail("Scope grant mission does not match")
    if grant.mission_context_hash != mission_context_hash:
        raise _fail("Scope grant mission context does not match")
    if grant.scope_reference != scope_reference:
        raise _fail("Scope grant scope reference does not match")
    if grant.scope_document_hash != scope_document_hash:
        raise _fail("Scope grant scope document does not match")
    if grant.environment is not environment:
        raise _fail("Scope grant environment does not match")
    if grant.max_action_tier is not max_action_tier:
        raise _fail("Scope grant maximum action tier does not match")
    if grant.constraints_hash != constraints_hash:
        raise _fail("Scope grant constraints do not match")
    if operation not in grant.operations:
        raise _fail("Requested operation is not in the scope grant")
    permit_expired = (
        allow_expired_for_safety_reduction
        and operation in SAFETY_REDUCING_OPERATIONS
    )
    now = _clock_value(clock)
    _verify_window(
        issued_at=verified_policy.policy.issued_at,
        not_before=verified_policy.policy.not_before,
        expires_at=verified_policy.policy.expires_at,
        now=now,
        label="principal trust policy",
    )
    scope_active = _verify_window(
        issued_at=grant.issued_at,
        not_before=grant.not_before,
        expires_at=grant.expires_at,
        now=now,
        label="scope grant",
        maximum_lifetime_seconds=verified_policy.policy.max_scope_lifetime_seconds,
        allow_expired=permit_expired,
    )
    scope_expires = _parse_timestamp(grant.expires_at)
    if (
        not scope_active
        and now
        >= scope_expires
        + timedelta(seconds=EXPIRED_SCOPE_STOP_GRACE_SECONDS)
    ):
        raise _fail("Expired scope grant is outside the safety-reduction grace period")
    if scope_expires > _parse_timestamp(verified_policy.policy.expires_at):
        raise _fail("Scope grant expires after its trust policy")
    key = _verify_policy_key(
        verified_policy,
        key_id=grant.key_id,
        required_key_use=TrustKeyUse.SCOPE_GRANT,
        issuer=grant.issuer,
        profile_id=grant.profile_id,
        subject=grant.subject,
        operations=grant.operations,
        issued_at=grant.issued_at,
        now=now,
    )
    _verify_ed25519(key.ed25519_public_key(), grant.signature, grant.signing_bytes(), "Scope grant")
    grant_sha256 = grant.content_sha256
    key_sha256 = key.content_sha256
    verified_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    safety_reduction_only = not scope_active
    return VerifiedScopeGrant(
        grant=grant,
        grant_sha256=grant_sha256,
        key_sha256=key_sha256,
        policy_sha256=verified_policy.policy_sha256,
        verified_operation=operation,
        scope_active=scope_active,
        safety_reduction_only=safety_reduction_only,
        verified_at=verified_at,
        _proof=_verification_proof(
            "verified_scope_grant",
            {
                "grant": grant.to_dict(),
                "grant_sha256": grant_sha256,
                "key_sha256": key_sha256,
                "policy_sha256": verified_policy.policy_sha256,
                "safety_reduction_only": safety_reduction_only,
                "scope_active": scope_active,
                "verified_at": verified_at,
                "verified_operation": operation.value,
            },
        ),
    )


def verify_scope_grant_revocation(
    revocation: ScopeGrantRevocation,
    verified_policy: VerifiedTrustPolicy,
    target_grant: ScopeGrant,
    *,
    expected_audience: str,
    expected_store_id: str,
    expected_mission_id: str,
    expected_mission_context_hash: str,
    clock: Callable[[], datetime],
) -> VerifiedScopeGrantRevocation:
    """Verify a signed revocation against its policy and exact target grant."""

    if not isinstance(revocation, ScopeGrantRevocation):
        raise _fail("revocation must be a ScopeGrantRevocation")
    revocation = ScopeGrantRevocation.from_dict(revocation.to_dict())
    if not isinstance(verified_policy, VerifiedTrustPolicy):
        raise _fail("verified_policy must be a VerifiedTrustPolicy")
    if not verified_policy._proof_is_valid():
        raise _fail("verified_policy was not produced by verify_trust_policy")
    if not isinstance(target_grant, ScopeGrant):
        raise _fail("target_grant must be a ScopeGrant")
    target_grant = ScopeGrant.from_dict(target_grant.to_dict())
    audience = _identifier(expected_audience, "expected_audience")
    store_id = _store_id(expected_store_id, "expected_store_id")
    mission_id = _mission_id(expected_mission_id, "expected_mission_id")
    mission_context_hash = _sha256(
        expected_mission_context_hash,
        "expected_mission_context_hash",
    )
    policy = verified_policy.policy
    if revocation.policy_id != policy.policy_id:
        raise _fail(
            "Scope grant revocation policy does not match the verified trust policy"
        )
    if revocation.policy_version != policy.policy_version:
        raise _fail(
            "Scope grant revocation policy version does not match the "
            "verified trust policy"
        )
    if revocation.audience != audience or revocation.audience != policy.audience:
        raise _fail("Scope grant revocation audience does not match")
    if revocation.store_id != store_id or revocation.store_id != policy.store_id:
        raise _fail("Scope grant revocation store does not match")
    if revocation.mission_id != mission_id:
        raise _fail("Scope grant revocation mission does not match")
    if revocation.mission_context_hash != mission_context_hash:
        raise _fail("Scope grant revocation mission context does not match")
    target_grant_sha256 = target_grant.content_sha256
    if revocation.scope_grant_issuer != target_grant.issuer:
        raise _fail("Scope grant revocation target issuer does not match")
    if revocation.scope_grant_id != target_grant.grant_id:
        raise _fail("Scope grant revocation target grant ID does not match")
    if revocation.scope_grant_sha256 != target_grant_sha256:
        raise _fail("Scope grant revocation target grant hash does not match")
    if revocation.scope_grant_subject != target_grant.subject:
        raise _fail("Scope grant revocation target subject does not match")
    if revocation.scope_grant_profile_id != target_grant.profile_id:
        raise _fail("Scope grant revocation target profile does not match")
    if target_grant.audience != revocation.audience:
        raise _fail("Scope grant revocation target audience does not match")
    if target_grant.store_id != revocation.store_id:
        raise _fail("Scope grant revocation target store does not match")
    if target_grant.mission_id != revocation.mission_id:
        raise _fail("Scope grant revocation target mission does not match")
    if target_grant.mission_context_hash != revocation.mission_context_hash:
        raise _fail("Scope grant revocation target mission context does not match")
    now = _clock_value(clock)
    _verify_window(
        issued_at=policy.issued_at,
        not_before=policy.not_before,
        expires_at=policy.expires_at,
        now=now,
        label="principal trust policy",
    )
    _verify_window(
        issued_at=revocation.issued_at,
        not_before=revocation.not_before,
        expires_at=revocation.expires_at,
        now=now,
        label="scope grant revocation",
        maximum_lifetime_seconds=policy.max_assertion_lifetime_seconds,
    )
    if _parse_timestamp(revocation.expires_at) > _parse_timestamp(
        policy.expires_at
    ):
        raise _fail("Scope grant revocation expires after its trust policy")
    key = _verify_policy_key(
        verified_policy,
        key_id=revocation.key_id,
        required_key_use=TrustKeyUse.SCOPE_GRANT_REVOCATION,
        issuer=revocation.issuer,
        profile_id=target_grant.profile_id,
        subject=target_grant.subject,
        operations=target_grant.operations,
        issued_at=revocation.issued_at,
        now=now,
    )
    _verify_ed25519(
        key.ed25519_public_key(),
        revocation.signature,
        revocation.signing_bytes(),
        "Scope grant revocation",
    )
    revocation_sha256 = revocation.content_sha256
    key_sha256 = key.content_sha256
    verified_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    proof_material = {
        "revocation": revocation.to_dict(),
        "revocation_sha256": revocation_sha256,
        "target_grant_sha256": target_grant_sha256,
        "key_sha256": key_sha256,
        "policy_sha256": verified_policy.policy_sha256,
        "verified_at": verified_at,
    }
    return VerifiedScopeGrantRevocation(
        revocation=revocation,
        revocation_sha256=revocation_sha256,
        target_grant_sha256=target_grant_sha256,
        key_sha256=key_sha256,
        policy_sha256=verified_policy.policy_sha256,
        verified_at=verified_at,
        _proof=_verification_proof(
            "verified_scope_grant_revocation",
            proof_material,
        ),
    )


def verify_principal_assertion(
    assertion: PrincipalAssertion,
    verified_policy: VerifiedTrustPolicy,
    verified_scope: VerifiedScopeGrant,
    *,
    expected_audience: str,
    expected_store_id: str,
    expected_mission_id: str,
    expected_operation: PrincipalOperation | str,
    expected_operation_intent_sha256: str,
    clock: Callable[[], datetime],
) -> VerifiedPrincipal:
    """Verify an assertion and derive the authenticated runtime principal."""

    if not isinstance(assertion, PrincipalAssertion):
        raise _fail("assertion must be a PrincipalAssertion")
    assertion = PrincipalAssertion.from_dict(assertion.to_dict())
    if not isinstance(verified_policy, VerifiedTrustPolicy):
        raise _fail("verified_policy must be a VerifiedTrustPolicy")
    if not isinstance(verified_scope, VerifiedScopeGrant):
        raise _fail("verified_scope must be a VerifiedScopeGrant")
    if not verified_policy._proof_is_valid():
        raise _fail("verified_policy was not produced by verify_trust_policy")
    if not verified_scope._proof_is_valid():
        raise _fail("verified_scope was not produced by verify_scope_grant")
    operation = _operation(
        expected_operation.value
        if isinstance(expected_operation, PrincipalOperation)
        else expected_operation,
        "expected_operation",
    )
    intent_sha256 = _sha256(
        expected_operation_intent_sha256,
        "expected_operation_intent_sha256",
    )
    audience = _identifier(expected_audience, "expected_audience")
    store_id = _store_id(expected_store_id, "expected_store_id")
    mission_id = _mission_id(expected_mission_id, "expected_mission_id")
    policy = verified_policy.policy
    scope = verified_scope.grant
    if verified_scope.policy_sha256 != verified_policy.policy_sha256:
        raise _fail("Verified scope does not belong to the verified trust policy")
    if verified_scope.verified_operation is not operation:
        raise _fail("Verified scope operation does not match the assertion operation")
    if verified_scope.safety_reduction_only and operation not in SAFETY_REDUCING_OPERATIONS:
        raise _fail("An inactive scope can authorize only a safety-reducing operation")
    if assertion.policy_id != policy.policy_id:
        raise _fail("Principal assertion policy does not match")
    if assertion.policy_version != policy.policy_version:
        raise _fail("Principal assertion policy version does not match")
    if assertion.scope_grant_id != scope.grant_id:
        raise _fail("Principal assertion scope grant ID does not match")
    if assertion.scope_grant_sha256 != verified_scope.grant_sha256:
        raise _fail("Principal assertion scope grant hash does not match")
    if assertion.subject != scope.subject or assertion.profile_id != scope.profile_id:
        raise _fail("Principal assertion identity does not match its scope grant")
    if assertion.audience != audience or assertion.audience != scope.audience:
        raise _fail("Principal assertion audience does not match")
    if assertion.store_id != store_id or assertion.store_id != scope.store_id:
        raise _fail("Principal assertion store does not match")
    if assertion.mission_id != mission_id or assertion.mission_id != scope.mission_id:
        raise _fail("Principal assertion mission does not match")
    if assertion.operation is not operation:
        raise _fail("Principal assertion operation does not match")
    if operation not in scope.operations:
        raise _fail("Principal assertion operation is not in its scope grant")
    if assertion.operation_intent_sha256 != intent_sha256:
        raise _fail("Principal assertion operation intent does not match")
    now = _clock_value(clock)
    _verify_window(
        issued_at=policy.issued_at,
        not_before=policy.not_before,
        expires_at=policy.expires_at,
        now=now,
        label="principal trust policy",
    )
    scope_active_now = _verify_window(
        issued_at=scope.issued_at,
        not_before=scope.not_before,
        expires_at=scope.expires_at,
        now=now,
        label="scope grant",
        maximum_lifetime_seconds=policy.max_scope_lifetime_seconds,
        allow_expired=operation in SAFETY_REDUCING_OPERATIONS,
    )
    scope_expires = _parse_timestamp(scope.expires_at)
    if (
        not scope_active_now
        and now
        >= scope_expires
        + timedelta(seconds=EXPIRED_SCOPE_STOP_GRACE_SECONDS)
    ):
        raise _fail("Expired scope grant is outside the safety-reduction grace period")
    scope_key = _verify_policy_key(
        verified_policy,
        key_id=scope.key_id,
        required_key_use=TrustKeyUse.SCOPE_GRANT,
        issuer=scope.issuer,
        profile_id=scope.profile_id,
        subject=scope.subject,
        operations=scope.operations,
        issued_at=scope.issued_at,
        now=now,
    )
    if scope_key.content_sha256 != verified_scope.key_sha256:
        raise _fail("Verified scope key does not match the current trust policy")
    _verify_ed25519(
        scope_key.ed25519_public_key(),
        scope.signature,
        scope.signing_bytes(),
        "Scope grant",
    )
    _verify_window(
        issued_at=assertion.issued_at,
        not_before=assertion.not_before,
        expires_at=assertion.expires_at,
        now=now,
        label="principal assertion",
        maximum_lifetime_seconds=policy.max_assertion_lifetime_seconds,
    )
    if _parse_timestamp(assertion.expires_at) > _parse_timestamp(policy.expires_at):
        raise _fail("Principal assertion expires after its trust policy")
    assertion_issued = _parse_timestamp(assertion.issued_at)
    assertion_not_before = _parse_timestamp(assertion.not_before)
    scope_not_before = _parse_timestamp(scope.not_before)
    assertion_expires = _parse_timestamp(assertion.expires_at)
    if assertion_issued < scope_not_before:
        raise _fail("Principal assertion was issued before its scope grant became active")
    if scope_active_now:
        if assertion_expires > scope_expires:
            raise _fail("Principal assertion expires after its scope grant")
    else:
        grace_expires = scope_expires + timedelta(
            seconds=EXPIRED_SCOPE_STOP_GRACE_SECONDS
        )
        if assertion_issued >= scope_expires:
            raise _fail(
                "Safety-reduction assertion must be issued before its scope grant expires"
            )
        if assertion_not_before >= scope_expires:
            raise _fail(
                "Safety-reduction assertion must become active before its scope grant expires"
            )
        if assertion_expires > grace_expires:
            raise _fail(
                "Safety-reduction assertion expires after the expired-scope grace period"
            )
    key = _verify_policy_key(
        verified_policy,
        key_id=assertion.key_id,
        required_key_use=TrustKeyUse.PRINCIPAL_ASSERTION,
        issuer=assertion.issuer,
        profile_id=assertion.profile_id,
        subject=assertion.subject,
        operations=(assertion.operation,),
        issued_at=assertion.issued_at,
        now=now,
    )
    _verify_ed25519(
        key.ed25519_public_key(),
        assertion.signature,
        assertion.signing_bytes(),
        "Principal assertion",
    )
    authenticated_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    principal_material = {
        "assertion_id": assertion.assertion_id,
        "assertion_sha256": assertion.content_sha256,
        "subject": assertion.subject,
        "profile_id": assertion.profile_id,
        "issuer": assertion.issuer,
        "key_id": assertion.key_id,
        "key_sha256": key.content_sha256,
        "policy_id": assertion.policy_id,
        "policy_version": policy.policy_version,
        "policy_sha256": verified_policy.policy_sha256,
        "scope_grant_id": assertion.scope_grant_id,
        "scope_grant_sha256": assertion.scope_grant_sha256,
        "audience": assertion.audience,
        "store_id": assertion.store_id,
        "mission_id": assertion.mission_id,
        "operation": assertion.operation.value,
        "operation_intent_sha256": assertion.operation_intent_sha256,
        "authenticated_at": authenticated_at,
        "expires_at": assertion.expires_at,
    }
    return VerifiedPrincipal(
        assertion_id=assertion.assertion_id,
        assertion_sha256=assertion.content_sha256,
        subject=assertion.subject,
        profile_id=assertion.profile_id,
        issuer=assertion.issuer,
        key_id=assertion.key_id,
        key_sha256=key.content_sha256,
        policy_id=assertion.policy_id,
        policy_version=policy.policy_version,
        policy_sha256=verified_policy.policy_sha256,
        scope_grant_id=assertion.scope_grant_id,
        scope_grant_sha256=assertion.scope_grant_sha256,
        audience=assertion.audience,
        store_id=assertion.store_id,
        mission_id=assertion.mission_id,
        operation=assertion.operation,
        operation_intent_sha256=assertion.operation_intent_sha256,
        authenticated_at=authenticated_at,
        expires_at=assertion.expires_at,
        _proof=_verification_proof(
            "verified_principal",
            principal_material,
        ),
    )


__all__ = [
    "OPERATION_INTENT_HASH_DOMAIN",
    "PRINCIPAL_ASSERTION_SIGNING_DOMAIN",
    "SAFETY_REDUCING_OPERATIONS",
    "SCOPE_GRANT_SIGNING_DOMAIN",
    "SCOPE_GRANT_REVOCATION_SIGNING_DOMAIN",
    "TRUST_POLICY_SIGNING_DOMAIN",
    "PrincipalAssertion",
    "PrincipalOperation",
    "PrincipalTrustPolicy",
    "ScopeGrant",
    "ScopeGrantRevocation",
    "TrustKey",
    "TrustKeyState",
    "TrustKeyUse",
    "VerifiedPrincipal",
    "VerifiedScopeGrant",
    "VerifiedScopeGrantRevocation",
    "VerifiedTrustPolicy",
    "compute_operation_intent_hash",
    "load_principal_assertion",
    "load_principal_trust_policy",
    "load_scope_grant",
    "load_scope_grant_revocation",
    "load_trust_policy",
    "validate_operation_intent",
    "verify_principal_assertion",
    "verify_scope_grant",
    "verify_scope_grant_revocation",
    "verify_trust_policy",
]
